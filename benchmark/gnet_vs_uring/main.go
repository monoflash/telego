package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/gnet/v2"
)

const (
	tlsHeaderSize     = 5
	tlsRecordTypeData = 0x17
	maxTLSPayload     = 16384

	// Backpressure settings (matching telego)
	maxWriteBuffer = 4 * 1024 * 1024 // 4MB hard limit
	softLimit      = 2 * 1024 * 1024 // 2MB soft limit
	resumeAt       = 1 * 1024 * 1024 // 1MB resume threshold
	relayBufSize   = 64 * 1024       // 64KB batch buffer
)

// Buffer pools - matching telego settings
var (
	relayBufPool = sync.Pool{New: func() any { b := make([]byte, maxTLSPayload); return &b }}
	dcBufPool    = sync.Pool{New: func() any { b := make([]byte, relayBufSize+256); return &b }}
)

// Stats for backpressure monitoring
var (
	backpressureHits  atomic.Int64
	hardLimitCloses   atomic.Int64
	totalBytesRelayed atomic.Int64
)

func main() {
	mode := flag.String("mode", "memtest", "Mode")
	flag.Parse()

	switch *mode {
	case "memtest":
		runMemTest()
	case "churn":
		runChurnTest()
	case "slowclient":
		runSlowClientTest()
	case "abandon":
		runAbandonTest()
	default:
		fmt.Println("Usage: -mode=memtest|churn|slowclient|abandon")
		os.Exit(1)
	}
}

// === Crypto context ===

type CryptoCtx struct {
	ClientDecrypt cipher.Stream
	ClientEncrypt cipher.Stream
	DCDecrypt     cipher.Stream
	DCEncrypt     cipher.Stream
}

func NewCryptoCtx() *CryptoCtx {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)
	block, _ := aes.NewCipher(key)
	return &CryptoCtx{
		ClientDecrypt: cipher.NewCTR(block, iv),
		ClientEncrypt: cipher.NewCTR(block, iv),
		DCDecrypt:     cipher.NewCTR(block, iv),
		DCEncrypt:     cipher.NewCTR(block, iv),
	}
}

// === Proxy server ===

type proxyServer struct {
	gnet.BuiltinEventEngine
	dcClient   *gnet.Client
	cryptoPool sync.Pool
}

type clientCtx struct {
	crypto *CryptoCtx
	dcConn gnet.Conn
}

func (s *proxyServer) OnBoot(eng gnet.Engine) gnet.Action {
	fmt.Println("Proxy server started on :9000")
	return gnet.None
}

func (s *proxyServer) OnOpen(c gnet.Conn) ([]byte, gnet.Action) {
	crypto := s.cryptoPool.Get().(*CryptoCtx)

	tcpConn, err := net.Dial("tcp", "localhost:9001")
	if err != nil {
		s.cryptoPool.Put(crypto)
		return nil, gnet.Close
	}

	dcConn, err := s.dcClient.Enroll(tcpConn)
	if err != nil {
		tcpConn.Close()
		s.cryptoPool.Put(crypto)
		return nil, gnet.Close
	}

	dcConn.SetContext(&dcConnCtx{clientConn: c, crypto: crypto})
	c.SetContext(&clientCtx{crypto: crypto, dcConn: dcConn})
	return nil, gnet.None
}

func (s *proxyServer) OnClose(c gnet.Conn, err error) gnet.Action {
	ctx, ok := c.Context().(*clientCtx)
	if ok && ctx != nil {
		if ctx.dcConn != nil {
			ctx.dcConn.Close()
		}
		s.cryptoPool.Put(ctx.crypto)
	}
	return gnet.None
}

// OnTraffic handles client -> DC with backpressure
func (s *proxyServer) OnTraffic(c gnet.Conn) gnet.Action {
	ctx := c.Context().(*clientCtx)
	if ctx == nil || ctx.dcConn == nil {
		return gnet.Close
	}

	dcBuffered := ctx.dcConn.OutboundBuffered()

	// Hard limit - OOM protection
	if dcBuffered > maxWriteBuffer {
		hardLimitCloses.Add(1)
		return gnet.Close
	}

	data, _ := c.Peek(-1)
	if len(data) < tlsHeaderSize {
		return gnet.None
	}

	// Rate limiting based on DC buffer level
	var maxProcess int
	if dcBuffered > softLimit {
		maxProcess = 64 * 1024
		backpressureHits.Add(1)
	} else if dcBuffered > resumeAt {
		maxProcess = 256 * 1024
	} else {
		maxProcess = len(data)
	}

	batchBufPtr := dcBufPool.Get().(*[]byte)
	batchBuf := *batchBufPtr
	batchOffset := 0
	processed := 0
	consumed := 0
	rateLimited := false

	for len(data) >= tlsHeaderSize {
		if data[0] != tlsRecordTypeData {
			dcBufPool.Put(batchBufPtr)
			return gnet.Close
		}
		payloadLen := int(binary.BigEndian.Uint16(data[3:5]))
		recordLen := tlsHeaderSize + payloadLen
		if len(data) < recordLen {
			break
		}

		payload := data[tlsHeaderSize:recordLen]

		// Check rate limit (always process at least one record)
		if processed > 0 && processed+len(payload) > maxProcess {
			rateLimited = true
			break
		}

		// Flush if batch full
		if batchOffset+len(payload) > len(batchBuf) {
			if batchOffset > 0 {
				ctx.dcConn.Write(batchBuf[:batchOffset])
				batchOffset = 0
			}
		}

		ctx.crypto.ClientDecrypt.XORKeyStream(batchBuf[batchOffset:batchOffset+len(payload)], payload)
		ctx.crypto.DCEncrypt.XORKeyStream(batchBuf[batchOffset:batchOffset+len(payload)], batchBuf[batchOffset:batchOffset+len(payload)])
		batchOffset += len(payload)
		processed += len(payload)
		consumed += recordLen
		data = data[recordLen:]
	}

	if batchOffset > 0 {
		ctx.dcConn.Write(batchBuf[:batchOffset])
		totalBytesRelayed.Add(int64(batchOffset))
	}
	dcBufPool.Put(batchBufPtr)

	if consumed > 0 {
		c.Discard(consumed)
	}

	// Only wake if we rate-limited
	if rateLimited {
		c.Wake(nil)
	}

	return gnet.None
}

// === DC handler ===

type dcHandler struct {
	gnet.BuiltinEventEngine
}

type dcConnCtx struct {
	clientConn gnet.Conn
	crypto     *CryptoCtx
}

// OnTraffic handles DC -> client with backpressure
func (h *dcHandler) OnTraffic(c gnet.Conn) gnet.Action {
	ctx := c.Context().(*dcConnCtx)
	if ctx == nil || ctx.clientConn == nil {
		return gnet.Close
	}

	clientBuffered := ctx.clientConn.OutboundBuffered()

	// Hard limit - OOM protection
	if clientBuffered > maxWriteBuffer {
		hardLimitCloses.Add(1)
		return gnet.Close
	}

	data, _ := c.Peek(-1)
	if len(data) == 0 {
		return gnet.None
	}

	// Rate limiting based on client buffer level
	maxProcess := len(data)
	if clientBuffered > softLimit {
		maxProcess = 64 * 1024
		if maxProcess > len(data) {
			maxProcess = len(data)
		}
		backpressureHits.Add(1)
	} else if clientBuffered > resumeAt {
		maxProcess = 256 * 1024
		if maxProcess > len(data) {
			maxProcess = len(data)
		}
	}

	processData := data[:maxProcess]

	numRecords := (len(processData) + maxTLSPayload - 1) / maxTLSPayload
	tlsSize := len(processData) + numRecords*tlsHeaderSize

	tlsBufPtr := dcBufPool.Get().(*[]byte)
	var tlsBuf []byte
	if tlsSize <= len(*tlsBufPtr) {
		tlsBuf = (*tlsBufPtr)[:tlsSize]
	} else {
		dcBufPool.Put(tlsBufPtr)
		tlsBufPtr = nil
		tlsBuf = make([]byte, tlsSize)
	}

	srcOffset := 0
	dstOffset := 0
	for srcOffset < len(processData) {
		chunk := min(maxTLSPayload, len(processData)-srcOffset)
		tlsBuf[dstOffset] = tlsRecordTypeData
		tlsBuf[dstOffset+1] = 0x03
		tlsBuf[dstOffset+2] = 0x03
		tlsBuf[dstOffset+3] = byte(chunk >> 8)
		tlsBuf[dstOffset+4] = byte(chunk)
		dstOffset += tlsHeaderSize
		ctx.crypto.DCDecrypt.XORKeyStream(tlsBuf[dstOffset:dstOffset+chunk], processData[srcOffset:srcOffset+chunk])
		ctx.crypto.ClientEncrypt.XORKeyStream(tlsBuf[dstOffset:dstOffset+chunk], tlsBuf[dstOffset:dstOffset+chunk])
		dstOffset += chunk
		srcOffset += chunk
	}

	c.Discard(len(processData))
	ctx.clientConn.Write(tlsBuf)
	totalBytesRelayed.Add(int64(len(processData)))

	if tlsBufPtr != nil {
		dcBufPool.Put(tlsBufPtr)
	}

	// Wake self if more data remaining
	if c.InboundBuffered() > 0 {
		c.Wake(nil)
	}

	return gnet.None
}

func (h *dcHandler) OnClose(c gnet.Conn, err error) gnet.Action {
	ctx, ok := c.Context().(*dcConnCtx)
	if ok && ctx != nil && ctx.clientConn != nil {
		ctx.clientConn.Close()
	}
	return gnet.None
}

// === DC echo server ===

type dcEchoServer struct {
	gnet.BuiltinEventEngine
	delay time.Duration
}

func (s *dcEchoServer) OnBoot(eng gnet.Engine) gnet.Action {
	if s.delay > 0 {
		fmt.Printf("DC echo server started on :9001 (delay=%v)\n", s.delay)
	} else {
		fmt.Println("DC echo server started on :9001")
	}
	return gnet.None
}

func (s *dcEchoServer) OnTraffic(c gnet.Conn) gnet.Action {
	data, _ := c.Next(-1)
	if len(data) > 0 {
		if s.delay > 0 {
			time.Sleep(s.delay)
		}
		c.Write(data)
	}
	return gnet.None
}

// === Start servers ===

func startServers() *gnet.Client {
	go func() {
		gnet.Run(&dcEchoServer{}, "tcp://:9001",
			gnet.WithMulticore(true),
			gnet.WithReadBufferCap(128*1024),
			gnet.WithWriteBufferCap(256*1024),
		)
	}()
	time.Sleep(500 * time.Millisecond)

	dcH := &dcHandler{}
	dcClient, _ := gnet.NewClient(dcH,
		gnet.WithMulticore(true),
		gnet.WithReadBufferCap(128*1024),
		gnet.WithWriteBufferCap(256*1024),
	)
	dcClient.Start()

	server := &proxyServer{
		dcClient:   dcClient,
		cryptoPool: sync.Pool{New: func() any { return NewCryptoCtx() }},
	}

	go func() {
		gnet.Run(server, "tcp://:9000",
			gnet.WithMulticore(true),
			gnet.WithReadBufferCap(128*1024),
			gnet.WithWriteBufferCap(256*1024),
		)
	}()
	time.Sleep(500 * time.Millisecond)

	return dcClient
}

// === Connection churn test ===

func runChurnTest() {
	fmt.Println("=== Connection Churn Test ===")
	fmt.Println("Rapid connect/disconnect to stress pool growth")
	fmt.Println()

	startServers()

	var totalConns atomic.Int64
	var wg sync.WaitGroup
	duration := 60 * time.Second
	done := make(chan struct{})

	fmt.Printf("Running churn test for %v\n", duration)
	printMemStats("Initial")

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			payload := make([]byte, 4096)
			rand.Read(payload)
			record := make([]byte, tlsHeaderSize+len(payload))
			record[0] = tlsRecordTypeData
			record[1] = 0x03
			record[2] = 0x03
			binary.BigEndian.PutUint16(record[3:5], uint16(len(payload)))
			copy(record[5:], payload)
			recvBuf := make([]byte, len(record)*2)

			for {
				select {
				case <-done:
					return
				default:
				}

				conn, err := net.Dial("tcp", "localhost:9000")
				if err != nil {
					continue
				}

				conn.SetDeadline(time.Now().Add(2 * time.Second))
				conn.Write(record)
				conn.Read(recvBuf)
				conn.Close()
				totalConns.Add(1)
			}
		}()
	}

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				printMemStatsWithBackpressure(fmt.Sprintf("%d total connections", totalConns.Load()))
			}
		}
	}()

	time.Sleep(duration)
	close(done)
	wg.Wait()

	runtime.GC()
	time.Sleep(time.Second)
	printMemStatsWithBackpressure("Final (after GC)")
	fmt.Printf("Total connections: %d\n", totalConns.Load())
}

// === Regular memory test ===

func runMemTest() {
	fmt.Println("=== Telego Memory Test with Backpressure ===")
	fmt.Println("1000 clients, 64KB buffers, 4MB hard limit, 2MB soft limit")
	fmt.Println()

	startServers()

	var activeConns atomic.Int32
	var totalMsgs atomic.Int64
	var wg sync.WaitGroup

	numConns := 1000
	duration := 60 * time.Second
	done := make(chan struct{})

	fmt.Printf("Starting %d connections for %v\n", numConns, duration)
	printMemStats("Initial")

	for i := 0; i < numConns; i++ {
		time.Sleep(5 * time.Millisecond)
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer activeConns.Add(-1)

			conn, err := net.Dial("tcp", "localhost:9000")
			if err != nil {
				return
			}
			defer conn.Close()
			activeConns.Add(1)

			payload := make([]byte, 4096)
			rand.Read(payload)
			record := make([]byte, tlsHeaderSize+len(payload))
			record[0] = tlsRecordTypeData
			record[1] = 0x03
			record[2] = 0x03
			binary.BigEndian.PutUint16(record[3:5], uint16(len(payload)))
			copy(record[5:], payload)
			recvBuf := make([]byte, len(record)*2)

			for {
				select {
				case <-done:
					return
				default:
				}
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err := conn.Write(record); err != nil {
					return
				}
				if _, err := conn.Read(recvBuf); err != nil {
					return
				}
				totalMsgs.Add(1)
				time.Sleep(time.Duration(1+id%10) * time.Millisecond)
			}
		}(i)
	}

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				printMemStatsWithBackpressure(fmt.Sprintf("%d conns, %d msgs", activeConns.Load(), totalMsgs.Load()))
			}
		}
	}()

	time.Sleep(duration)
	close(done)
	wg.Wait()

	runtime.GC()
	time.Sleep(time.Second)
	printMemStatsWithBackpressure("Final (after GC)")
	fmt.Printf("Total messages: %d\n", totalMsgs.Load())
}

func printMemStats(label string) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("[%s] Heap=%dMB Sys=%dMB Objects=%d GCs=%d Goroutines=%d\n",
		label, m.HeapInuse/1024/1024, m.Sys/1024/1024,
		m.HeapObjects, m.NumGC, runtime.NumGoroutine())
}

func printMemStatsWithBackpressure(label string) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("[%s] Heap=%dMB Sys=%dMB BP=%d HardClose=%d Relayed=%dMB\n",
		label, m.HeapInuse/1024/1024, m.Sys/1024/1024,
		backpressureHits.Load(), hardLimitCloses.Load(),
		totalBytesRelayed.Load()/1024/1024)
}

// === Slow Client test - simulates mobile clients on bad network ===

func runSlowClientTest() {
	fmt.Println("=== Slow Client Test with Backpressure ===")
	fmt.Println("Clients send data but NEVER read responses")
	fmt.Println("Proxy's client write buffer MUST fill up")
	fmt.Println()

	// Use normal fast servers
	startServers()

	var activeConns atomic.Int32
	var totalMsgs atomic.Int64
	var wg sync.WaitGroup

	numConns := 100
	duration := 60 * time.Second
	done := make(chan struct{})

	fmt.Printf("Starting %d non-reading clients for %v\n", numConns, duration)
	printMemStats("Initial")

	for i := 0; i < numConns; i++ {
		time.Sleep(50 * time.Millisecond)
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer activeConns.Add(-1)

			conn, err := net.Dial("tcp", "localhost:9000")
			if err != nil {
				return
			}
			defer conn.Close()
			activeConns.Add(1)

			// Large payload - 16KB per message
			payload := make([]byte, 16384)
			rand.Read(payload)
			record := make([]byte, tlsHeaderSize+len(payload))
			record[0] = tlsRecordTypeData
			record[1] = 0x03
			record[2] = 0x03
			binary.BigEndian.PutUint16(record[3:5], uint16(len(payload)))
			copy(record[5:], payload)

			// Keep sending forever, NEVER read
			// This will cause proxy's write buffer to fill
			for {
				select {
				case <-done:
					return
				default:
				}

				conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
				_, err := conn.Write(record)
				if err != nil {
					// Write failed - likely write buffer full (good!) or connection closed
					time.Sleep(100 * time.Millisecond)
					continue
				}
				totalMsgs.Add(1)
			}
		}(i)
	}

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				printMemStatsWithBackpressure(fmt.Sprintf("%d conns, %d msgs", activeConns.Load(), totalMsgs.Load()))
			}
		}
	}()

	time.Sleep(duration)
	close(done)
	wg.Wait()

	runtime.GC()
	time.Sleep(time.Second)
	printMemStatsWithBackpressure("Final (after GC)")
	fmt.Printf("Total messages: %d\n", totalMsgs.Load())
}

// === Abandon test - clients disconnect mid-transmission ===

func runAbandonTest() {
	fmt.Println("=== Abandon Test with Backpressure ===")
	fmt.Println("Clients send large data then disconnect immediately")
	fmt.Println("Simulates clients dropping during file transfer")
	fmt.Println()

	startServers()

	var totalAbandons atomic.Int64
	var wg sync.WaitGroup

	duration := 180 * time.Second
	done := make(chan struct{})
	numWorkers := 200

	fmt.Printf("Running abandon test for %v with %d workers\n", duration, numWorkers)
	printMemStats("Initial")

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			payload := make([]byte, 16384)
			rand.Read(payload)

			for {
				select {
				case <-done:
					return
				default:
				}

				conn, err := net.Dial("tcp", "localhost:9000")
				if err != nil {
					time.Sleep(10 * time.Millisecond)
					continue
				}

				for j := 0; j < 20; j++ {
					record := make([]byte, tlsHeaderSize+len(payload))
					record[0] = tlsRecordTypeData
					record[1] = 0x03
					record[2] = 0x03
					binary.BigEndian.PutUint16(record[3:5], uint16(len(payload)))
					copy(record[5:], payload)
					conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
					conn.Write(record)
				}

				conn.Close()
				totalAbandons.Add(1)
			}
		}()
	}

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				printMemStatsWithBackpressure(fmt.Sprintf("%d abandons", totalAbandons.Load()))
			}
		}
	}()

	time.Sleep(duration)
	close(done)
	wg.Wait()

	runtime.GC()
	time.Sleep(2 * time.Second)
	printMemStatsWithBackpressure("Final (after GC)")
	fmt.Printf("Total abandoned connections: %d\n", totalAbandons.Load())
}
