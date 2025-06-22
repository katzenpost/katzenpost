// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/katzenpost/client2/thin"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

// removeCapabilityFromDedup removes a capability from the deduplication maps
// This should be called when a channel is explicitly closed or removed
func (d *Daemon) removeCapabilityFromDedup(channelDesc *ChannelDescriptor) {
	if channelDesc.StatefulReader != nil {
		readCapBytes, err := channelDesc.StatefulReader.Rcap.MarshalBinary()
		if err == nil {
			capHash := hash.Sum256(readCapBytes)
			d.capabilityLock.Lock()
			delete(d.usedReadCaps, capHash)
			d.capabilityLock.Unlock()
		}
		return
	}
	if channelDesc.StatefulWriter != nil {
		boxOwnerCapBytes, err := channelDesc.StatefulWriter.Wcap.MarshalBinary()
		if err == nil {
			capHash := hash.Sum256(boxOwnerCapBytes)
			d.capabilityLock.Lock()
			delete(d.usedWriteCaps, capHash)
			d.capabilityLock.Unlock()
		}
	}
}

func (d *Daemon) sendCreateWriteChannelError(request *Request, errorCode uint8) {
	conn := d.listener.getConnection(request.AppID)
	if conn != nil {
		conn.sendResponse(&Response{
			AppID: request.AppID,
			CreateWriteChannelReply: &thin.CreateWriteChannelReply{
				ChannelID: 0,
				ErrorCode: errorCode,
			},
		})
	}
}

func (d *Daemon) sendCreateReadChannelError(request *Request, errorCode uint8) {
	conn := d.listener.getConnection(request.AppID)
	if conn != nil {
		conn.sendResponse(&Response{
			AppID: request.AppID,
			CreateReadChannelReply: &thin.CreateReadChannelReply{
				ChannelID: 0,
				ErrorCode: errorCode,
			},
		})
	}
}

func (d *Daemon) sendReadChannelError(request *Request, errorCode uint8) {
	conn := d.listener.getConnection(request.AppID)
	if conn != nil {
		conn.sendResponse(&Response{
			AppID: request.AppID,
			ReadChannelReply: &thin.ReadChannelReply{
				MessageID: request.ReadChannel.MessageID,
				ChannelID: request.ReadChannel.ChannelID,
				ErrorCode: errorCode,
			},
		})
	}
}

func (d *Daemon) sendWriteChannelError(request *Request, errorCode uint8) {
	conn := d.listener.getConnection(request.AppID)
	if conn != nil {
		conn.sendResponse(&Response{
			AppID: request.AppID,
			WriteChannelReply: &thin.WriteChannelReply{
				ChannelID: request.WriteChannel.ChannelID,
				ErrorCode: errorCode,
			},
		})
	}
}

func (d *Daemon) handleChannelReplyError(appID *[AppIDLength]byte, surbID *[sphinxConstants.SURBIDLength]byte, messageID *[MessageIDLength]byte, errorCode uint8) {
	conn := d.listener.getConnection(appID)
	if conn != nil {
		conn.sendResponse(&Response{
			AppID: appID,
			MessageReplyEvent: &thin.MessageReplyEvent{
				MessageID: messageID,
				SURBID:    surbID,
				ErrorCode: errorCode,
				Payload:   []byte{},
			},
		})
	}
}
