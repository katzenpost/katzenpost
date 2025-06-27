package deoxysii

// sliceForAppend extends the capacity of `in` by `n` octets, returning the
// potentially new slice and the appended portion.
//
// This routine is cribbed from the Go standard library and `x/crypto`.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
