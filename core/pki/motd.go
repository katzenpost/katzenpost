// SPDX-License-Identifier: AGPL-3.0-only

package pki

import "fmt"

const MaxMOTDLength = 1024

type MOTDError struct {
	Disallowed int
	Offset     int
	Byte       byte
	Cut        bool
	Limit      int
}

func (e *MOTDError) Error() string {
	if e.Disallowed > 0 {
		return fmt.Sprintf("motd has a disallowed byte 0x%02x at offset %d", e.Byte, e.Offset)
	}
	return fmt.Sprintf("motd exceeds %d bytes", e.Limit)
}

func PrintableMOTD(motd []byte, limit int) ([]byte, error) {
	limit = min(limit, MaxMOTDLength)
	out := make([]byte, 0, min(len(motd), limit))
	e := &MOTDError{Limit: limit}
	for i, c := range motd {
		switch {
		case c != '\n' && (c < 0x20 || c > 0x7e):
			if e.Disallowed == 0 {
				e.Offset, e.Byte = i, c
			}
			e.Disallowed++
		case len(out) == limit:
			e.Cut = true
		default:
			out = append(out, c)
		}
	}
	if e.Disallowed == 0 && !e.Cut {
		return out, nil
	}
	return out, e
}
