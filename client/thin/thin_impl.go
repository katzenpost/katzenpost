// SPDX-FileCopyrightText: © 2023, 2024, 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package thin provides a lightweight client API for the Katzenpost mixnet.
//
// # Overview
//
// The thin client package implements a client-daemon architecture where the thin client
// communicates with a separate client daemon process that handles the heavy cryptographic
// operations and mixnet protocol details. This design allows applications to integrate
// with Katzenpost without implementing the full complexity of the mixnet protocols.
//
// # Architecture
//
// The thin client connects to a client daemon via TCP or Unix domain sockets. The daemon
// handles:
//   - Sphinx packet creation and processing
//   - PKI document management and validation
//   - Mixnet routing and timing
//   - Cryptographic operations (encryption, decryption, signatures)
//   - Connection management to the mixnet
//
// The thin client provides a simple API for:
//   - Sending and receiving messages
//   - Handling events and status updates
//
// # APIs
//
// This package provides two main APIs:
//
// ## Legacy API (deprecated for new projects)
//
// The legacy API provides basic message sending functionality:
//   - SendMessage: Send a message with optional reply capability
//   - SendMessageWithoutReply: Send a fire-and-forget message
//   - BlockingSendMessage: Send a message and wait for reply
//
// Note: ARQ (Automatic Repeat reQuest) is now used exclusively for the new Pigeonhole API.
//
// ## Pigeonhole Channel API
//
// For more information about this API please see our API documentation, here:
// https://katzenpost.network/docs/client_integration/#pigeonhole-channel-api
//
// The Pigeonhole protocol provides the following messages and their corresponding
// replies/events:
//   - NewKeypair
//   - EncryptRead
//   - EncryptWrite
//   - StartResendingEncryptedMessage
//   - CancelResendingEncryptedMessage
//   - StartResendingCopyCommand
//   - CancelResendingCopyCommand
//   - NextMessageBoxIndex
//   - CreateCourierEnvelopesFromPayload
//   - CreateCourierEnvelopesFromPayloads
//   - SetStreamBuffer
//
// # Configuration
//
// The thin client requires configuration specifying:
//   - Network and address of the client daemon
//   - Sphinx geometry parameters
//   - Pigeonhole geometry parameters
//

//go:build !wasm

// See the testdata/thinclient.toml file for an example configuration.
package thin

import (
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin/transport"
)

// FromConfig creates a thin client Config from a client daemon config.Config.
//
// This function extracts the daemon's listen address and creates a thin
// client configuration that can connect to that daemon. Geometry is no
// longer copied here: the daemon delivers it over the handshake.
//
// Parameters:
//   - cfg: The client daemon configuration
//
// Returns:
//   - *Config: A thin client configuration compatible with the daemon
//
// Panics:
//   - If cfg.Listen is nil
func FromConfig(cfg *config.Config) *Config {
	if cfg.Listen == nil {
		panic("Listen cannot be nil")
	}

	dial := &transport.DialConfig{}
	switch {
	case cfg.Listen.Unix != nil:
		dial.Unix = &transport.UnixDialConfig{Address: cfg.Listen.Unix.Address}
	case cfg.Listen.Tcp != nil:
		dial.Tcp = &transport.TcpDialConfig{
			Address: cfg.Listen.Tcp.Address,
			Network: cfg.Listen.Tcp.Network,
		}
	case cfg.Listen.Ws != nil:
		dial.Ws = &transport.WsDialConfig{
			Address: cfg.Listen.Ws.Address,
		}
	default:
		panic("Listen has no transport configured")
	}

	return &Config{
		Dial: dial,
	}
}
