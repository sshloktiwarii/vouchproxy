package crypto

import "runtime"

// ZeroBytes actively overwrites all bytes in the given slice with 0x00,
// and enforces a memory barrier via runtime.KeepAlive to ensure the compiler
// does not optimize away the loop before memory synchronization.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
