// SPDX-License-Identifier: AGPL-3.0-only

package pki

import "fmt"

const (
	maxMinClientVersionLength = 32
	maxClientNoticeLength     = 512
)

func printableWithin(name, v string, n int) error {
	if len(v) > n {
		return fmt.Errorf("%s exceeds %d bytes", name, n)
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			return fmt.Errorf("%s has a non-printable byte at %d", name, i)
		}
	}
	return nil
}

func IsClientNoticeWellFormed(minClientVersion, notice string) error {
	if err := printableWithin("MinClientVersion", minClientVersion, maxMinClientVersionLength); err != nil {
		return err
	}
	return printableWithin("ClientNotice", notice, maxClientNoticeLength)
}
