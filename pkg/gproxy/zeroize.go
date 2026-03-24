package gproxy

// Zeroize overwrites a byte slice with zeros.
// This is used for secure cleanup of sensitive data like session IDs.
//
// Note: Go's compiler may optimize away zeroing of "dead" variables.
// For maximum security, call this before the variable goes out of scope
// while it's still reachable.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ZeroizeArray32 zeros a 32-byte array in place.
func ZeroizeArray32(arr *[32]byte) {
	for i := range arr {
		arr[i] = 0
	}
}
