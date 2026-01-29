// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/client2/common"
	"github.com/katzenpost/katzenpost/core/epochtime"
)

/***

This file contains the OLD Pigeonhole API.
It should be removed once the new Pigeonhole API is fully implemented.

***/

// CreateWriteChannel creates a new Pigeonhole write channel for sending messages.
//
// This method creates a new communication channel using the Pigeonhole protocol,
// which provides reliable, ordered message delivery. The channel is created with
// fresh cryptographic capabilities that allow writing messages to the channel
// and sharing read access with other parties.
//
// The returned capabilities have the following purposes:
//   - ReadCap: Can be shared with others to allow them to read messages from this channel
//   - WriteCap: Should be stored securely for channel persistence and resumption
//   - ChannelID: Used for subsequent operations on this channel
//
// Channel operations work in offline mode (when daemon is not connected to mixnet),
// allowing applications to prepare messages even without network connectivity.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//
// Returns:
//   - uint16: Channel ID for subsequent operations
//   - *bacap.ReadCap: Read capability that can be shared with message recipients
//   - *bacap.WriteCap: Write capability for channel persistence and resumption
//   - error: Any error encountered during channel creation
//
// Example:
//
//	ctx := context.Background()
//	channelID, readCap, writeCap, err := client.CreateWriteChannel(ctx)
//	if err != nil {
//		log.Fatal("Failed to create write channel:", err)
//	}
//
//	// Share readCap with Bob so he can read messages
//	// Store writeCap for channel resumption after restart
//	fmt.Printf("Created channel %d\n", channelID)
func (t *ThinClient) CreateWriteChannel(ctx context.Context) (uint16, *bacap.ReadCap, *bacap.WriteCap, error) {
	if ctx == nil {
		return 0, nil, nil, errContextCannotBeNil
	}

	queryID := t.NewQueryID()
	req := &Request{
		CreateWriteChannel: &CreateWriteChannel{
			QueryID: queryID,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
	if err != nil {
		return 0, nil, nil, err
	}

	for {
		var event Event
		select {
		case <-ctx.Done():
			return 0, nil, nil, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return 0, nil, nil, errHalting
		}

		switch v := event.(type) {
		case *CreateWriteChannelReply:
			if v.QueryID == nil {
				t.log.Debugf("CreateWriteChannel: Received CreateWriteChannelReply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("CreateWriteChannel: Received CreateWriteChannelReply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return 0, nil, nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.ChannelID, v.ReadCap, v.WriteCap, nil
		case *ConnectionStatusEvent:
			// Update connection state but don't fail channel operations
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// CreateReadChannel creates a read channel from a read capability.
//
// This method creates a channel for reading messages using a read capability
// that was obtained from the creator of a write channel. The read capability
// allows access to messages written to the corresponding write channel.
//
// Read channels maintain their own state independent of the write channel,
// allowing multiple readers to consume messages at their own pace. Each
// reader tracks its own position in the message sequence.
//
// Like other channel operations, this works in offline mode, allowing
// applications to set up channels even when the daemon is not connected
// to the mixnet.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - readCap: Read capability obtained from the channel creator
//
// Returns:
//   - uint16: Channel ID for subsequent read operations
//   - error: Any error encountered during channel creation
//
// Example:
//
//	// Bob creates a read channel using Alice's read capability
//	ctx := context.Background()
//	channelID, err := client.CreateReadChannel(ctx, readCap)
//	if err != nil {
//		log.Fatal("Failed to create read channel:", err)
//	}
//
//	// Now Bob can read messages from Alice's channel
//	fmt.Printf("Created read channel %d\n", channelID)
func (t *ThinClient) CreateReadChannel(ctx context.Context, readCap *bacap.ReadCap) (uint16, error) {
	if ctx == nil {
		return 0, errContextCannotBeNil
	}
	if readCap == nil {
		return 0, errors.New("readCap cannot be nil")
	}
	queryID := t.NewQueryID()

	req := &Request{
		CreateReadChannel: &CreateReadChannel{
			QueryID: queryID,
			ReadCap: readCap,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
	if err != nil {
		return 0, err
	}

	for {
		var event Event
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return 0, errHalting
		}

		switch v := event.(type) {
		case *CreateReadChannelReply:
			if v.QueryID == nil {
				t.log.Debugf("CreateReadChannel: Received CreateReadChannelReply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("CreateReadChannel: Received CreateReadChannelReply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return 0, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.ChannelID, nil
		case *ConnectionStatusEvent:
			// Update connection state but don't fail channel operations
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// WriteChannel prepares a message for writing to a Pigeonhole channel.
//
// This method performs the first step of the two-phase channel write process:
// it prepares the cryptographic payload that will be sent through the mixnet.
// The actual transmission is performed separately using SendChannelQuery().
//
// This separation allows for:
//   - State management and persistence between preparation and transmission
//   - Retry logic and error recovery
//   - Offline operation (preparation works without mixnet connectivity)
//
// The method validates the payload size against the configured Pigeonhole
// geometry limits and returns all information needed to complete the write
// operation, including state for resumption after interruption.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - channelID: Channel ID returned by CreateWriteChannel or ResumeWriteChannel
//   - payload: Message data to write (must not exceed MaxPlaintextPayloadLength)
//
// Returns:
//   - *WriteChannelReply: Contains prepared payload and state information
//   - error: Any error encountered during preparation
//
// Example:
//
//	message := []byte("Hello, Bob!")
//	writeReply, err := client.WriteChannel(ctx, channelID, message)
//	if err != nil {
//		log.Fatal("Failed to prepare write:", err)
//	}
//
//	// Now send the prepared message
//	destNode, destQueue, _ := client.GetCourierDestination()
//	messageID := client.NewMessageID()
//	_, err = client.SendChannelQueryAwaitReply(ctx, channelID,
//		writeReply.SendMessagePayload, destNode, destQueue, messageID)
func (t *ThinClient) WriteChannel(ctx context.Context, channelID uint16, payload []byte) (*WriteChannelReply, error) {
	if ctx == nil {
		return nil, errContextCannotBeNil
	}

	queryID := t.NewQueryID()

	// Validate payload size against pigeonhole geometry
	if len(payload) > t.cfg.PigeonholeGeometry.MaxPlaintextPayloadLength {
		return nil, fmt.Errorf("payload size %d exceeds maximum allowed size %d", len(payload), t.cfg.PigeonholeGeometry.MaxPlaintextPayloadLength)
	}

	req := &Request{
		WriteChannel: &WriteChannel{
			ChannelID: channelID,
			QueryID:   queryID,
			Payload:   payload,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
	if err != nil {
		return nil, err
	}

	for {
		var event Event
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return nil, errHalting
		}

		switch v := event.(type) {
		// match our queryID
		case *WriteChannelReply:
			if v.QueryID == nil {
				t.log.Debugf("WriteChannel: Received WriteChannelReply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("WriteChannel: Received WriteChannelReply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v, nil
		case *ConnectionStatusEvent:
			// Update connection state but don't fail channel operations
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// ResumeWriteChannel resumes a write channel from a previous session.
//
// This method allows applications to restore a write channel after a restart
// or interruption by providing the write capability and message index that
// were saved from a previous session. This enables persistent communication
// channels that survive application restarts.
//
// The write capability and message index should be obtained from:
//   - CreateWriteChannelReply.WriteCap and CreateWriteChannelReply.NextMessageIndex
//   - WriteChannelReply.NextMessageIndex from previous write operations
//
// After resumption, the channel can be used normally with WriteChannel()
// and other channel operations.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - writeCap: Write capability from the original channel creation
//   - messageBoxIndex: Message index to resume from (typically the next index to write);
//     if set to nil then the channel will start from the beginning.
//
// Returns:
//   - uint16: Channel ID for subsequent operations on the resumed channel
//   - error: Any error encountered during resumption
//
// Example:
//
//	// During application shutdown, save these values persistently:
//	// writeCap (from CreateWriteChannelReply)
//	// nextMessageIndex (from last WriteChannelReply)
//
//	// After restart, resume the channel:
//	channelID, err := client.ResumeWriteChannel(ctx, writeCap, nextMessageIndex)
//	if err != nil {
//		log.Fatal("Failed to resume write channel:", err)
//	}
//
//	// Continue using the channel normally
//	message := []byte("Resumed channel message")
//	writeReply, err := client.WriteChannel(ctx, channelID, message)
func (t *ThinClient) ResumeWriteChannel(
	ctx context.Context,
	writeCap *bacap.WriteCap,
	messageBoxIndex *bacap.MessageBoxIndex) (uint16, error) {

	if ctx == nil {
		return 0, errContextCannotBeNil
	}
	if writeCap == nil {
		return 0, errors.New("writeCap cannot be nil")
	}
	queryID := t.NewQueryID()

	req := &Request{
		ResumeWriteChannel: &ResumeWriteChannel{
			QueryID:         queryID,
			WriteCap:        writeCap,
			MessageBoxIndex: messageBoxIndex,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
	if err != nil {
		return 0, err
	}
	for {
		var event Event
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return 0, errHalting
		}

		switch v := event.(type) {
		// match our queryID
		case *ResumeWriteChannelReply:
			if v.QueryID == nil {
				t.log.Debugf("ResumeWriteChannel: Received ResumeWriteChannelReply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("ResumeWriteChannel: Received ResumeWriteChannelReply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return 0, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.ChannelID, nil
		case *ConnectionStatusEvent:
			// Update connection state but don't fail channel operations
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// ResumeWriteChannelQuery resumes a write channel with a specific query state.
//
// This method provides more granular resumption control than ResumeWriteChannel
// by allowing the application to resume from a specific query state, including
// the envelope descriptor and hash. This is useful when resuming from a partially
// completed write operation that was interrupted during transmission.
//
// This method is typically used when an application has saved the complete state
// from a WriteChannelReply and wants to resume from that exact point, including
// any pending query state.
//
// All parameters are required for this method, unlike the basic ResumeWriteChannel
// which only requires the write capability and message index.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - writeCap: Write capability from the original channel creation
//   - messageBoxIndex: Exact message index to resume from
//   - envelopeDescriptor: Envelope descriptor from the interrupted operation
//   - envelopeHash: Hash of the envelope from the interrupted operation
//
// Returns:
//   - uint16: Channel ID for subsequent operations on the resumed channel
//   - error: Any error encountered during resumption
//
// Example:
//
//	// During interruption, save complete state from WriteChannelReply:
//	// writeCap, messageBoxIndex, envelopeDescriptor, envelopeHash
//
//	// Resume with complete query state:
//	channelID, err := client.ResumeWriteChannelQuery(ctx, writeCap,
//		messageBoxIndex, envelopeDescriptor, envelopeHash)
//	if err != nil {
//		log.Fatal("Failed to resume write channel query:", err)
//	}
//
//	// Channel is now ready to continue from the exact interrupted state
func (t *ThinClient) ResumeWriteChannelQuery(
	ctx context.Context,
	writeCap *bacap.WriteCap,
	messageBoxIndex *bacap.MessageBoxIndex,
	envelopeDescriptor []byte,
	envelopeHash *[32]byte) (uint16, error) {

	if ctx == nil {
		return 0, errContextCannotBeNil
	}
	if writeCap == nil {
		return 0, errors.New("writeCap cannot be nil")
	}
	queryID := t.NewQueryID()

	req := &Request{
		ResumeWriteChannelQuery: &ResumeWriteChannelQuery{
			QueryID:            queryID,
			WriteCap:           writeCap,
			MessageBoxIndex:    messageBoxIndex,
			EnvelopeDescriptor: envelopeDescriptor,
			EnvelopeHash:       envelopeHash,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
	if err != nil {
		return 0, err
	}
	for {
		var event Event
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return 0, errHalting
		}

		switch v := event.(type) {
		// match our queryID
		case *ResumeWriteChannelQueryReply:
			if v.QueryID == nil {
				t.log.Debugf("ResumeWriteChannel: Received ResumeWriteChannelReply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("ResumeWriteChannel: Received ResumeWriteChannelReply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return 0, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.ChannelID, nil
		case *ConnectionStatusEvent:
			// Update connection state but don't fail channel operations
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// ReadChannel prepares a read query for a Pigeonhole channel.
//
// This method performs the first step of the two-phase channel read process:
// it prepares the cryptographic query that will be sent through the mixnet
// to retrieve the next message from the channel. The actual transmission is
// performed separately using SendChannelQuery() or SendChannelQueryAwaitReply().
//
// Note that the last two parameters are useful if you want to send two read
// queries to the same Box id in order to retrieve two different replies. Our
// current sharding scheme ensures that two storage replicas will store a copy
// of the Box we are interested in reading. Thus we can optionally select the
// specific storage replica to query.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - channelID: Channel ID returned by CreateReadChannel or ResumeReadChannel
//   - messageBoxIndex: Optional specific message index to read (nil for next message)
//   - replyIndex: Optional specific reply index within the message (nil for default)
//
// Returns:
//   - *ReadChannelReply: Contains prepared query payload and state information
//   - error: Any error encountered during preparation
//
// Example:
//
//	// Read the next message in sequence
//	readReply, err := client.ReadChannel(ctx, channelID, nil, nil)
//	if err != nil {
//		log.Fatal("Failed to prepare read:", err)
//	}
//
//	// Send the prepared query
//	destNode, destQueue, _ := client.GetCourierDestination()
//	messageID := client.NewMessageID()
//	replyPayload, err := client.SendChannelQueryAwaitReply(ctx, channelID,
//		readReply.SendMessagePayload, destNode, destQueue, messageID)
func (t *ThinClient) ReadChannel(ctx context.Context, channelID uint16, messageBoxIndex *bacap.MessageBoxIndex, replyIndex *uint8) (*ReadChannelReply, error) {
	if ctx == nil {
		return nil, errContextCannotBeNil
	}

	queryID := t.NewQueryID()

	req := &Request{
		ReadChannel: &ReadChannel{
			ChannelID:       channelID,
			QueryID:         queryID,
			MessageBoxIndex: messageBoxIndex,
			ReplyIndex:      replyIndex,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.writeMessage(req)
	if err != nil {
		return nil, err
	}

	for {
		var event Event
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return nil, errHalting
		}

		switch v := event.(type) {
		// match our queryID
		case *ReadChannelReply:
			if v.QueryID == nil {
				t.log.Debugf("ReadChannel: Received ReadChannelReply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v, nil
		case *ConnectionStatusEvent:
			// Update connection state but don't fail channel operations
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// ResumeReadChannel resumes a read channel from a previous session.
//
// This method allows applications to restore a read channel after a restart
// or interruption by providing the read capability and position information
// that were saved from a previous session. This enables persistent communication
// channels that survive application restarts.
//
// The read capability should be obtained from the channel creator, and the
// position information should be saved from previous read operations to
// maintain proper message sequencing.
//
// After resumption, the channel can be used normally with ReadChannel()
// and other channel operations.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - readCap: Read capability obtained from the channel creator
//   - nextMessageIndex: Message index to resume from. If set to nil then the channel
//     will start from the beginning index value indicated by the readCap.
//   - replyIndex: Reply index within the message (nil for default)
//
// Returns:
//   - uint16: Channel ID for subsequent operations on the resumed channel
//   - error: Any error encountered during resumption
//
// Example:
//
//	// During application shutdown, save these values persistently:
//	// readCap (from channel creator)
//	// nextMessageIndex (from last ReadChannelReply)
//	// replyIndex (from last ReadChannelReply)
//
//	// After restart, resume the channel:
//	channelID, err := client.ResumeReadChannel(ctx, readCap,
//		nextMessageIndex, replyIndex)
//	if err != nil {
//		log.Fatal("Failed to resume read channel:", err)
//	}
//
//	// Continue reading messages normally
//	readReply, err := client.ReadChannel(ctx, channelID, nil, nil)
func (t *ThinClient) ResumeReadChannel(
	ctx context.Context,
	readCap *bacap.ReadCap,
	nextMessageIndex *bacap.MessageBoxIndex,
	replyIndex *uint8) (uint16, error) {

	queryID := t.NewQueryID()
	req := &Request{
		ResumeReadChannel: &ResumeReadChannel{
			QueryID:          queryID,
			ReadCap:          readCap,
			NextMessageIndex: nextMessageIndex,
			ReplyIndex:       replyIndex,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)
	err := t.writeMessage(req)
	if err != nil {
		return 0, err
	}
	for {
		var event Event
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return 0, errHalting
		}

		switch v := event.(type) {
		// match our queryID
		case *ResumeReadChannelReply:
			if v.QueryID == nil {
				t.log.Debugf("ResumeReadChannel: Received ResumeReadChannelReply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("ResumeReadChannel: Received ResumeReadChannelReply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return 0, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.ChannelID, nil
		case *ConnectionStatusEvent:
			// Update connection state but don't fail channel operations
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// ResumeReadChannelQuery resumes a read channel with a specific query state.
//
// This method provides more granular resumption control than ResumeReadChannel
// by allowing the application to resume from a specific query state, including
// the envelope descriptor and hash. This is useful when resuming from a partially
// completed read operation that was interrupted during transmission.
//
// This method is typically used when an application has saved the complete state
// from a ReadChannelReply and wants to resume from that exact point, including
// any pending query state.
//
// Most parameters are required for this method. Only replyIndex may be nil,
// in which case it defaults to 0 (the first reply in the message).
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - readCap: Read capability obtained from the channel creator
//   - nextMessageIndex: Exact message index to resume from (required)
//   - replyIndex: Reply index within the message (nil defaults to 0)
//   - envelopeDescriptor: Envelope descriptor from the interrupted operation (required)
//   - envelopeHash: Hash of the envelope from the interrupted operation (required)
//
// Returns:
//   - uint16: Channel ID for subsequent operations on the resumed channel
//   - error: Any error encountered during resumption
//
// Example:
//
//	// During interruption, save complete state from ReadChannelReply:
//	// readCap, nextMessageIndex, replyIndex, envelopeDescriptor, envelopeHash
//
//	// Resume with complete query state:
//	channelID, err := client.ResumeReadChannelQuery(ctx, readCap,
//		nextMessageIndex, replyIndex, envelopeDescriptor, envelopeHash)
//	if err != nil {
//		log.Fatal("Failed to resume read channel query:", err)
//	}
//
//	// Channel is now ready to continue from the exact interrupted state
func (t *ThinClient) ResumeReadChannelQuery(
	ctx context.Context,
	readCap *bacap.ReadCap,
	nextMessageIndex *bacap.MessageBoxIndex,
	replyIndex *uint8,
	envelopeDescriptor []byte,
	envelopeHash *[32]byte) (uint16, error) {

	queryID := t.NewQueryID()
	req := &Request{
		ResumeReadChannelQuery: &ResumeReadChannelQuery{
			QueryID:            queryID,
			ReadCap:            readCap,
			NextMessageIndex:   nextMessageIndex,
			ReplyIndex:         replyIndex,
			EnvelopeDescriptor: envelopeDescriptor,
			EnvelopeHash:       envelopeHash,
		},
	}

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)
	err := t.writeMessage(req)
	if err != nil {
		return 0, err
	}
	for {
		var event Event
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return 0, errHalting
		}

		switch v := event.(type) {
		// match our queryID
		case *ResumeReadChannelQueryReply:
			if v.QueryID == nil {
				t.log.Debugf("ResumeReadChannelQuery: Received ResumeReadChannelQueryReply with nil QueryID, ignoring")
				continue
			}
			if !bytes.Equal(v.QueryID[:], queryID[:]) {
				t.log.Debugf("ResumeReadChannelQuery: Received ResumeReadChannelQueryReply with mismatched QueryID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return 0, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.ChannelID, nil
		case *ConnectionStatusEvent:
			// Update connection state but don't fail channel operations
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// CloseChannel closes a Pigeonhole channel and releases its resources.
//
// This method cleanly closes a channel that was created with CreateWriteChannel,
// CreateReadChannel, or any of the Resume methods. Closing a channel releases
// the associated resources in the client daemon and should be called when the
// channel is no longer needed.
//
// After closing a channel, the channel ID becomes invalid and should not be
// used for further operations. Attempting to use a closed channel ID will
// result in errors.
//
// This operation works in both online and offline modes, as it only affects
// local state in the client daemon.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - channelID: Channel ID to close (from Create or Resume operations)
//
// Returns:
//   - error: Any error encountered during channel closure
//
// Example:
//
//	// Create a channel
//	channelID, readCap, writeCap, err := client.CreateWriteChannel(ctx)
//	if err != nil {
//		return err
//	}
//
//	// Use the channel for operations...
//	// ...
//
//	// Clean up when done
//	err = client.CloseChannel(ctx, channelID)
//	if err != nil {
//		log.Printf("Warning: failed to close channel %d: %v", channelID, err)
//	}
//
//	// Store writeCap and readCap for future resumption if needed
func (t *ThinClient) CloseChannel(ctx context.Context, channelID uint16) error {
	if ctx == nil {
		return errContextCannotBeNil
	}

	req := &Request{
		CloseChannel: &CloseChannel{
			ChannelID: channelID,
		},
	}

	return t.writeMessage(req)
}

// SendChannelQuery sends a prepared channel query to the mixnet without waiting for a reply.
//
// This method performs the second step of the two-phase channel operation process.
// It takes a payload prepared by WriteChannel or ReadChannel and transmits it
// through the mixnet to the specified courier service.
//
// This is a fire-and-forget operation - it does not wait for a reply. Use
// SendChannelQueryAwaitReply if you need to wait for and receive the response.
//
// Requirements:
//   - The daemon must be connected to the mixnet (IsConnected() == true)
//   - The payload must be prepared by WriteChannel or ReadChannel
//   - The destination must be obtained from GetCourierDestination()
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - channelID: Channel ID from CreateWriteChannel/CreateReadChannel/Resume operations
//   - payload: Prepared payload from WriteChannel or ReadChannel
//   - destNode: Courier service node hash from GetCourierDestination()
//   - destQueue: Courier service queue ID from GetCourierDestination()
//   - messageID: Unique message identifier for correlation
//
// Returns:
//   - error: Any error encountered during transmission
//
// Example:
//
//	// Prepare a write operation
//	writeReply, err := client.WriteChannel(ctx, channelID, message)
//	if err != nil {
//		return err
//	}
//
//	// Get courier destination
//	destNode, destQueue, err := client.GetCourierDestination()
//	if err != nil {
//		return err
//	}
//
//	// Send without waiting for reply
//	messageID := client.NewMessageID()
//	err = client.SendChannelQuery(ctx, channelID, writeReply.SendMessagePayload,
//		destNode, destQueue, messageID)
func (t *ThinClient) SendChannelQuery(
	ctx context.Context,
	channelID uint16,
	payload []byte,
	destNode *[32]byte,
	destQueue []byte,
	messageID *[MessageIDLength]byte,
) error {

	if ctx == nil {
		return errContextCannotBeNil
	}

	// Check if we're in offline mode
	if !t.isConnected {
		return errors.New("cannot send channel query in offline mode - daemon not connected to mixnet")
	}

	req := &Request{
		SendChannelQuery: &SendChannelQuery{
			MessageID:         messageID,
			ChannelID:         &channelID,
			Payload:           payload,
			DestinationIdHash: destNode,
			RecipientQueueID:  destQueue,
		},
	}

	return t.writeMessage(req)
}

// SendChannelQueryAwaitReply sends a prepared channel query and waits for the reply.
//
// This method performs the second step of the two-phase channel operation process
// and blocks until a reply is received or the context times out. It combines
// sending the prepared payload with waiting for and returning the response.
//
// This is the most commonly used method for channel operations as it provides
// a complete request-response cycle. For fire-and-forget operations, use
// SendChannelQuery instead.
//
// Requirements:
//   - The daemon must be connected to the mixnet (IsConnected() == true)
//   - The payload must be prepared by WriteChannel or ReadChannel
//   - The destination must be obtained from GetCourierDestination()
//
// Parameters:
//   - ctx: Context for cancellation and timeout control (recommended: 30s timeout)
//   - channelID: Channel ID from CreateWriteChannel/CreateReadChannel/Resume operations
//   - payload: Prepared payload from WriteChannel or ReadChannel
//   - destNode: Courier service node hash from GetCourierDestination()
//   - destQueue: Courier service queue ID from GetCourierDestination()
//   - messageID: Unique message identifier for correlation
//
// Returns:
//   - []byte: Response payload from the courier service
//   - error: Any error encountered during transmission or while waiting for reply
//
// Example:
//
//	// Prepare a read operation
//	readReply, err := client.ReadChannel(ctx, channelID, nil, nil)
//	if err != nil {
//		return err
//	}
//
//	// Get courier destination
//	destNode, destQueue, err := client.GetCourierDestination()
//	if err != nil {
//		return err
//	}
//
//	// Send and wait for reply
//	messageID := client.NewMessageID()
//	replyPayload, err := client.SendChannelQueryAwaitReply(ctx, channelID,
//		readReply.SendMessagePayload, destNode, destQueue, messageID)
//	if err != nil {
//		return err
//	}
//
//	// Process the received message
//	fmt.Printf("Received: %s\n", replyPayload)
func (t *ThinClient) SendChannelQueryAwaitReply(
	ctx context.Context,
	channelID uint16,
	payload []byte,
	destNode *[32]byte,
	destQueue []byte,
	messageID *[MessageIDLength]byte,
) ([]byte, error) {

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	err := t.SendChannelQuery(ctx, channelID, payload, destNode, destQueue, messageID)
	if err != nil {
		return nil, err
	}
	for {
		var event Event
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case event = <-eventSink:
		case <-t.HaltCh():
			return nil, errHalting
		}

		switch v := event.(type) {
		case *ChannelQuerySentEvent:
			if v.MessageID == nil {
				t.log.Debugf("SendChannelQueryAwaitReply: Received ChannelQuerySentEvent with nil MessageID, ignoring")
				continue
			}
			if !bytes.Equal(v.MessageID[:], messageID[:]) {
				t.log.Debugf("SendChannelQueryAwaitReply: Received ChannelQuerySentEvent with mismatched MessageID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			continue
		case *ChannelQueryReplyEvent:
			if v.MessageID == nil {
				t.log.Debugf("SendChannelQueryAwaitReply: Received MessageReplyEvent with nil MessageID, ignoring")
				continue
			}
			if !bytes.Equal(v.MessageID[:], messageID[:]) {
				t.log.Debugf("SendChannelQueryAwaitReply: Received MessageReplyEvent with mismatched MessageID, ignoring")
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return nil, errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return v.Payload, nil
		case *ConnectionStatusEvent:
			// Update connection state but don't fail channel operations
			t.isConnected = v.IsConnected
		case *NewDocumentEvent:
			// Ignore PKI document updates
		default:
			// Ignore other events
		}
	}
}

// GetCourierDestination returns a courier service destination for the current epoch.
//
// This method finds and randomly selects a courier service from the current
// PKI document. Courier services handle Pigeonhole protocol operations,
// storing and retrieving messages for channels. The random selection provides
// automatic load balancing across available courier instances.
//
// The returned destination information is used with SendChannelQuery and
// SendChannelQueryAwaitReply to transmit prepared channel operations to
// the mixnet.
//
// Returns:
//   - *[32]byte: Hash of the courier service's identity key (destination node)
//   - []byte: Queue ID for the courier service
//   - error: Error if no courier services are available
//
// Example:
//
//	// Get courier destination for sending a channel query
//	destNode, destQueue, err := client.GetCourierDestination()
//	if err != nil {
//		log.Fatal("No courier services available:", err)
//	}
//
//	// Use with SendChannelQuery
//	messageID := client.NewMessageID()
//	err = client.SendChannelQuery(ctx, channelID, payload,
//		destNode, destQueue, messageID)
func (t *ThinClient) GetCourierDestination() (*[32]byte, []byte, error) {
	epoch, _, _ := epochtime.Now()
	epochDoc, err := t.PKIDocumentForEpoch(epoch)
	if err != nil {
		return nil, nil, err
	}
	courierServices := common.FindServices("courier", epochDoc)
	if len(courierServices) == 0 {
		return nil, nil, errors.New("no courier services found")
	}
	// Select a random courier service for load distribution
	courierService := courierServices[rand.NewMath().Intn(len(courierServices))]
	destNode := hash.Sum256(courierService.MixDescriptor.IdentityKey)
	destQueue := courierService.RecipientQueueID
	return &destNode, destQueue, nil
}
