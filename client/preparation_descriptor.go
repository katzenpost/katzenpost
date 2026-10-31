// SPDX-License-Identifier: AGPL-3.0-only

package client

import "github.com/katzenpost/katzenpost/core/utils"

// preparationDescriptor owns the serialized private descriptor until the
// response queue accepts it. The caller must defer dispose immediately after
// serialization, including when serialization returns an error.
type preparationDescriptor struct {
	bytes []byte
}

func (d *preparationDescriptor) dispose() {
	utils.ExplicitBzero(d.bytes)
	d.bytes = nil
}

// enqueue transfers ownership only on successful enqueue. The asynchronous
// writer still needs the response's original buffer after this call returns.
func (d *preparationDescriptor) enqueue(conn *incomingConn, response *Response) error {
	if err := conn.sendResponse(response); err != nil {
		return err
	}
	d.bytes = nil
	return nil
}
