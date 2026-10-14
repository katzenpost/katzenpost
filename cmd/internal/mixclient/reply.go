// SPDX-License-Identifier: AGPL-3.0-only

package mixclient

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"gopkg.in/op/go-logging.v1"

	cpki "github.com/katzenpost/katzenpost/core/pki"
)

func PrintableReply(reply []byte, notices io.Writer, log *logging.Logger) []byte {
	log.Debugf("raw reply: %s", hex.EncodeToString(reply))
	text, err := cpki.PrintableMOTD(bytes.TrimRight(reply, "\x00"), cpki.MaxMOTDLength)
	var e *cpki.MOTDError
	if errors.As(err, &e) {
		if e.Disallowed > 0 {
			fmt.Fprintf(notices, "removed %d disallowed byte(s) from the reply\n", e.Disallowed)
		}
		if e.Cut {
			fmt.Fprintf(notices, "cut the reply at %d bytes\n", e.Limit)
		}
	}
	return text
}
