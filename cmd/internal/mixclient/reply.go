// SPDX-License-Identifier: AGPL-3.0-only

package mixclient

import (
	"io"

	"gopkg.in/op/go-logging.v1"

	cpki "github.com/katzenpost/katzenpost/core/pki"
)

func PrintableReply(reply []byte, notices io.Writer, log *logging.Logger) []byte {
	text, _ := cpki.PrintableMOTD(reply, cpki.MaxMOTDLength)
	return text
}
