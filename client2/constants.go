// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

// Service constants
const (
	// EchoService is the standardized service string for the echo service.
	EchoService = "echo"
)

// State constants
const (
	// HaltingState indicates the client is halting.
	HaltingState = "halting"
)

// CBOR field constants
const (
	// ChannelIDField is the CBOR field name for channel ID.
	ChannelIDField = "channel_id"
	// PayloadField is the CBOR field name for payload.
	PayloadField = "payload"
	// MessageIDField is the CBOR field name for message ID.
	MessageIDField = "message_id"
	// ErrField is the CBOR field name for error (omitempty).
	ErrField = "err,omitempty"
)
