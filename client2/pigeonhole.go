// SPDX-FileCopyrightText: (c) 2026  David Stainton.
// SPDX-License-Identifier: AGPL-3.0-only
package client2

import (
	"github.com/katzenpost/hpqc/bacap"

	"github.com/katzenpost/katzenpost/client2/thin"
)

// newKeypair creates a new keypair for use with the Pigeonhole protocol.
func (d *Daemon) newKeypair(request *Request) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		d.sendReadChannelError(request, thin.ThinClientErrorConnectionLost)
		return
	}
	seed := request.NewKeypair.Seed
	writeCap, err := bacap.NewWriteCapFromBytes(seed)
	if err != nil {
		d.sendReadChannelError(request, thin.ThinClientErrorInvalidRequest)
		return
	}
	readCap := writeCap.ReadCap()
	conn.sendResponse(&Response{
		AppID: request.AppID,
		NewKeypairReply: &thin.NewKeypairReply{
			WriteCap:  writeCap,
			ReadCap:   readCap,
			ErrorCode: thin.ThinClientSuccess,
		},
	})
}
