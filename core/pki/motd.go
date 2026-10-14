// SPDX-License-Identifier: AGPL-3.0-only

package pki

import "fmt"

const MaxMOTDLength = 1024

func PrintableMOTD(motd []byte, limit int) ([]byte, error) {
	limit = min(limit, MaxMOTDLength)
	out := make([]byte, 0, min(len(motd), limit))
	var err error
	for i, c := range motd {
		switch {
		case c != '\n' && (c < 0x20 || c > 0x7e):
			if err == nil {
				err = fmt.Errorf("motd has a disallowed byte 0x%02x at offset %d", c, i)
			}
		case len(out) == limit:
			if err == nil {
				err = fmt.Errorf("motd exceeds %d bytes", limit)
			}
			return out, err
		default:
			out = append(out, c)
		}
	}
	return out, err
}
