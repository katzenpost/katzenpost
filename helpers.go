package ratchet

// Wipe wipes the insides of a byte array
func wipe(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
