// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonhole

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// Test error message constants to avoid duplication
const (
	errReplyIndexMismatch  = "ReplyIndex mismatch: got %d, want %d"
	errPayloadLenMismatch  = "PayloadLen mismatch: got %d, want %d"
	errPayloadMismatch     = "Payload mismatch"
	errErrorCodeMismatch   = "ErrorCode mismatch: got %d, want %d"
	errBoxIDMismatch       = "BoxID mismatch"
	errMessageTypeMismatch = "MessageType mismatch: got %d, want %d"
	errSignatureMismatch   = "Signature mismatch"
)

// Helper function to create random bytes
func randomBytes(size int) []byte {
	data := make([]byte, size)
	rand.Read(data)
	return data
}

// Helper function to create random fixed-size array
func randomFixedBytes32() [32]uint8 {
	var arr [32]uint8
	rand.Read(arr[:])
	return arr
}

func randomFixedBytes60() [60]uint8 {
	var arr [60]uint8
	rand.Read(arr[:])
	return arr
}

func randomFixedBytes64() [64]uint8 {
	var arr [64]uint8
	rand.Read(arr[:])
	return arr
}

func TestCourierEnvelopeEncodeDecode(t *testing.T) {
	// Create test data
	senderPubkey := randomBytes(32)
	ciphertext := randomBytes(100)

	original := &CourierEnvelope{
		IntermediateReplicas: [2]uint8{1, 2},
		Dek1:                 randomFixedBytes60(),
		Dek2:                 randomFixedBytes60(),
		ReplyIndex:           42,
		Epoch:                12345678901234567890,
		SenderPubkeyLen:      uint16(len(senderPubkey)),
		SenderPubkey:         senderPubkey,
		CiphertextLen:        uint32(len(ciphertext)),
		Ciphertext:           ciphertext,
		IsRead:               1,
	}

	// Encode
	encoded, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to encode CourierEnvelope: %v", err)
	}

	// Decode
	decoded := &CourierEnvelope{}
	_, err = decoded.Parse(encoded)
	if err != nil {
		t.Fatalf("Failed to decode CourierEnvelope: %v", err)
	}

	// Compare fields
	if decoded.IntermediateReplicas != original.IntermediateReplicas {
		t.Errorf("IntermediateReplicas mismatch: got %v, want %v", decoded.IntermediateReplicas, original.IntermediateReplicas)
	}
	if decoded.Dek1 != original.Dek1 {
		t.Errorf("Dek1 mismatch")
	}
	if decoded.Dek2 != original.Dek2 {
		t.Errorf("Dek2 mismatch")
	}
	if decoded.ReplyIndex != original.ReplyIndex {
		t.Errorf(errReplyIndexMismatch, decoded.ReplyIndex, original.ReplyIndex)
	}
	if decoded.Epoch != original.Epoch {
		t.Errorf("Epoch mismatch: got %d, want %d", decoded.Epoch, original.Epoch)
	}
	if decoded.SenderPubkeyLen != original.SenderPubkeyLen {
		t.Errorf("SenderPubkeyLen mismatch: got %d, want %d", decoded.SenderPubkeyLen, original.SenderPubkeyLen)
	}
	if !bytes.Equal(decoded.SenderPubkey, original.SenderPubkey) {
		t.Errorf("SenderPubkey mismatch")
	}
	if decoded.CiphertextLen != original.CiphertextLen {
		t.Errorf("CiphertextLen mismatch: got %d, want %d", decoded.CiphertextLen, original.CiphertextLen)
	}
	if !bytes.Equal(decoded.Ciphertext, original.Ciphertext) {
		t.Errorf("Ciphertext mismatch")
	}
	if decoded.IsRead != original.IsRead {
		t.Errorf("IsRead mismatch: got %d, want %d", decoded.IsRead, original.IsRead)
	}
}

func TestCourierEnvelopeReplyEncodeDecode(t *testing.T) {
	payload := randomBytes(50)
	envelopeHash := randomFixedBytes32()

	original := &CourierEnvelopeReply{
		EnvelopeHash: envelopeHash,
		ReplyIndex:   123,
		PayloadLen:   uint32(len(payload)),
		Payload:      payload,
		ErrorCode:    0,
	}

	// Encode
	encoded, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to encode CourierEnvelopeReply: %v", err)
	}

	// Decode
	decoded := &CourierEnvelopeReply{}
	_, err = decoded.Parse(encoded)
	if err != nil {
		t.Fatalf("Failed to decode CourierEnvelopeReply: %v", err)
	}

	// Compare fields
	if decoded.EnvelopeHash != original.EnvelopeHash {
		t.Errorf("EnvelopeHash mismatch")
	}
	if decoded.ReplyIndex != original.ReplyIndex {
		t.Errorf(errReplyIndexMismatch, decoded.ReplyIndex, original.ReplyIndex)
	}
	if decoded.PayloadLen != original.PayloadLen {
		t.Errorf(errPayloadLenMismatch, decoded.PayloadLen, original.PayloadLen)
	}
	if !bytes.Equal(decoded.Payload, original.Payload) {
		t.Errorf(errPayloadMismatch)
	}
	if decoded.ErrorCode != original.ErrorCode {
		t.Errorf(errErrorCodeMismatch, decoded.ErrorCode, original.ErrorCode)
	}
}

func TestReplicaReadEncodeDecode(t *testing.T) {
	original := &ReplicaRead{
		BoxID: randomFixedBytes32(),
	}

	// Encode
	encoded, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to encode ReplicaRead: %v", err)
	}

	// Decode
	decoded := &ReplicaRead{}
	_, err = decoded.Parse(encoded)
	if err != nil {
		t.Fatalf("Failed to decode ReplicaRead: %v", err)
	}

	// Compare fields
	if decoded.BoxID != original.BoxID {
		t.Errorf(errBoxIDMismatch)
	}
}

func TestReplicaReadReplyEncodeDecode(t *testing.T) {
	payload := randomBytes(75)

	original := &ReplicaReadReply{
		BoxID:      randomFixedBytes32(),
		ErrorCode:  1,
		PayloadLen: uint32(len(payload)),
		Payload:    payload,
		Signature:  randomFixedBytes64(),
	}

	// Note: ReplicaReadReply doesn't have a Bytes() method in methods.go
	// We need to test it through ReplicaMessageReplyInnerMessage
	replyMsg := &ReplicaMessageReplyInnerMessage{
		MessageType: 0, // Read reply
		ReadReply:   original,
	}

	// Encode
	encoded, err := replyMsg.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to encode ReplicaMessageReplyInnerMessage: %v", err)
	}

	// Decode
	decoded := &ReplicaMessageReplyInnerMessage{}
	_, err = decoded.Parse(encoded)
	if err != nil {
		t.Fatalf("Failed to decode ReplicaMessageReplyInnerMessage: %v", err)
	}

	// Compare fields
	if decoded.MessageType != replyMsg.MessageType {
		t.Errorf(errMessageTypeMismatch, decoded.MessageType, replyMsg.MessageType)
	}
	if decoded.ReadReply == nil {
		t.Fatalf("ReadReply is nil")
	}
	if decoded.ReadReply.BoxID != original.BoxID {
		t.Errorf(errBoxIDMismatch)
	}
	if decoded.ReadReply.ErrorCode != original.ErrorCode {
		t.Errorf(errErrorCodeMismatch, decoded.ReadReply.ErrorCode, original.ErrorCode)
	}
	if decoded.ReadReply.PayloadLen != original.PayloadLen {
		t.Errorf(errPayloadLenMismatch, decoded.ReadReply.PayloadLen, original.PayloadLen)
	}
	if !bytes.Equal(decoded.ReadReply.Payload, original.Payload) {
		t.Errorf(errPayloadMismatch)
	}
	if decoded.ReadReply.Signature != original.Signature {
		t.Errorf(errSignatureMismatch)
	}
}

func TestReplicaWriteEncodeDecode(t *testing.T) {
	payload := randomBytes(80)

	original := &ReplicaWrite{
		BoxID:      randomFixedBytes32(),
		Signature:  randomFixedBytes64(),
		PayloadLen: uint32(len(payload)),
		Payload:    payload,
	}

	// Encode
	encoded, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to encode ReplicaWrite: %v", err)
	}

	// Decode
	decoded := &ReplicaWrite{}
	_, err = decoded.Parse(encoded)
	if err != nil {
		t.Fatalf("Failed to decode ReplicaWrite: %v", err)
	}

	// Compare fields
	if decoded.BoxID != original.BoxID {
		t.Errorf(errBoxIDMismatch)
	}
	if decoded.Signature != original.Signature {
		t.Errorf(errSignatureMismatch)
	}
	if decoded.PayloadLen != original.PayloadLen {
		t.Errorf(errPayloadLenMismatch, decoded.PayloadLen, original.PayloadLen)
	}
	if !bytes.Equal(decoded.Payload, original.Payload) {
		t.Errorf(errPayloadMismatch)
	}
}

func TestReplicaWriteReplyEncodeDecode(t *testing.T) {
	original := &ReplicaWriteReply{
		ErrorCode: ReplicaErrorSuccess,
	}

	// Note: ReplicaWriteReply doesn't have a Bytes() method in methods.go
	// We need to test it through ReplicaMessageReplyInnerMessage
	replyMsg := &ReplicaMessageReplyInnerMessage{
		MessageType: 1, // Write reply
		WriteReply:  original,
	}

	// Encode
	encoded, err := replyMsg.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to encode ReplicaMessageReplyInnerMessage: %v", err)
	}

	// Decode
	decoded := &ReplicaMessageReplyInnerMessage{}
	_, err = decoded.Parse(encoded)
	if err != nil {
		t.Fatalf("Failed to decode ReplicaMessageReplyInnerMessage: %v", err)
	}

	// Compare fields
	if decoded.MessageType != replyMsg.MessageType {
		t.Errorf(errMessageTypeMismatch, decoded.MessageType, replyMsg.MessageType)
	}
	if decoded.WriteReply == nil {
		t.Fatalf("WriteReply is nil")
	}
	if decoded.WriteReply.ErrorCode != original.ErrorCode {
		t.Errorf(errErrorCodeMismatch, decoded.WriteReply.ErrorCode, original.ErrorCode)
	}
}

func TestReplicaInnerMessageReadEncodeDecode(t *testing.T) {
	readMsg := &ReplicaRead{
		BoxID: randomFixedBytes32(),
	}

	original := &ReplicaInnerMessage{
		MessageType: 0, // Read message
		ReadMsg:     readMsg,
	}

	// Encode
	encoded, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to encode ReplicaInnerMessage: %v", err)
	}

	// Decode
	decoded := &ReplicaInnerMessage{}
	_, err = decoded.Parse(encoded)
	if err != nil {
		t.Fatalf("Failed to decode ReplicaInnerMessage: %v", err)
	}

	// Compare fields
	if decoded.MessageType != original.MessageType {
		t.Errorf(errMessageTypeMismatch, decoded.MessageType, original.MessageType)
	}
	if decoded.ReadMsg == nil {
		t.Fatalf("ReadMsg is nil")
	}
	if decoded.ReadMsg.BoxID != original.ReadMsg.BoxID {
		t.Errorf("ReadMsg.BoxID mismatch")
	}
}

func TestReplicaInnerMessageWriteEncodeDecode(t *testing.T) {
	payload := randomBytes(60)
	writeMsg := &ReplicaWrite{
		BoxID:      randomFixedBytes32(),
		Signature:  randomFixedBytes64(),
		PayloadLen: uint32(len(payload)),
		Payload:    payload,
	}

	original := &ReplicaInnerMessage{
		MessageType: 1, // Write message
		WriteMsg:    writeMsg,
	}

	// Encode
	encoded, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to encode ReplicaInnerMessage: %v", err)
	}

	// Decode
	decoded := &ReplicaInnerMessage{}
	_, err = decoded.Parse(encoded)
	if err != nil {
		t.Fatalf("Failed to decode ReplicaInnerMessage: %v", err)
	}

	// Compare fields
	if decoded.MessageType != original.MessageType {
		t.Errorf(errMessageTypeMismatch, decoded.MessageType, original.MessageType)
	}
	if decoded.WriteMsg == nil {
		t.Fatalf("WriteMsg is nil")
	}
	if decoded.WriteMsg.BoxID != original.WriteMsg.BoxID {
		t.Errorf("WriteMsg.BoxID mismatch")
	}
	if decoded.WriteMsg.Signature != original.WriteMsg.Signature {
		t.Errorf("WriteMsg.Signature mismatch")
	}
	if decoded.WriteMsg.PayloadLen != original.WriteMsg.PayloadLen {
		t.Errorf(errPayloadLenMismatch, decoded.WriteMsg.PayloadLen, original.WriteMsg.PayloadLen)
	}
	if !bytes.Equal(decoded.WriteMsg.Payload, original.WriteMsg.Payload) {
		t.Errorf("WriteMsg.Payload mismatch")
	}
}

func TestBoxEncodeDecode(t *testing.T) {
	payload := randomBytes(90)

	original := &Box{
		BoxID:      randomFixedBytes32(),
		PayloadLen: uint32(len(payload)),
		Payload:    payload,
		Signature:  randomFixedBytes64(),
	}

	// Encode
	encoded, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to encode Box: %v", err)
	}

	// Decode
	decoded := &Box{}
	_, err = decoded.Parse(encoded)
	if err != nil {
		t.Fatalf("Failed to decode Box: %v", err)
	}

	// Compare fields
	if decoded.BoxID != original.BoxID {
		t.Errorf(errBoxIDMismatch)
	}
	if decoded.PayloadLen != original.PayloadLen {
		t.Errorf(errPayloadLenMismatch, decoded.PayloadLen, original.PayloadLen)
	}
	if !bytes.Equal(decoded.Payload, original.Payload) {
		t.Errorf(errPayloadMismatch)
	}
	if decoded.Signature != original.Signature {
		t.Errorf(errSignatureMismatch)
	}
}

func TestCourierQueryEncodeDecode(t *testing.T) {
	// Test copy command case
	copyCommand := &CopyCommand{
		WriteCapLen: 25,
		WriteCap:    randomBytes(25),
	}
	original := &CourierQuery{
		QueryType:   1, // 1 = copy_command
		CopyCommand: copyCommand,
	}

	// Encode
	encoded, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to encode CourierQuery: %v", err)
	}

	// Decode
	decoded := &CourierQuery{}
	_, err = decoded.Parse(encoded)
	if err != nil {
		t.Fatalf("Failed to decode CourierQuery: %v", err)
	}

	// Compare fields
	if decoded.QueryType != original.QueryType {
		t.Errorf("QueryType mismatch: got %d, want %d", decoded.QueryType, original.QueryType)
	}
	// For union type 1 (copy_command), check the CopyCommand field
	if original.QueryType == 1 {
		if decoded.CopyCommand == nil || original.CopyCommand == nil {
			t.Errorf("CopyCommand should not be nil for QueryType 1")
		} else {
			if !bytes.Equal(decoded.CopyCommand.WriteCap, original.CopyCommand.WriteCap) {
				t.Errorf("CopyCommand WriteCap mismatch")
			}
		}
	}
}

func TestCourierQueryReplyEncodeDecode(t *testing.T) {
	// Test copy command reply case
	copyCommandReply := &CopyCommandReply{
		ErrorCode: 1,
	}
	original := &CourierQueryReply{
		ReplyType:        1, // 1 = copy_command_reply
		CopyCommandReply: copyCommandReply,
	}

	// Encode
	encoded, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to encode CourierQueryReply: %v", err)
	}

	// Decode
	decoded := &CourierQueryReply{}
	_, err = decoded.Parse(encoded)
	if err != nil {
		t.Fatalf("Failed to decode CourierQueryReply: %v", err)
	}

	// Compare fields
	if decoded.ReplyType != original.ReplyType {
		t.Errorf("ReplyType mismatch: got %d, want %d", decoded.ReplyType, original.ReplyType)
	}
	// For union type 1 (copy_command_reply), check the CopyCommandReply field
	if original.ReplyType == 1 {
		if decoded.CopyCommandReply == nil || original.CopyCommandReply == nil {
			t.Errorf("CopyCommandReply should not be nil for ReplyType 1")
		} else {
			if decoded.CopyCommandReply.ErrorCode != original.CopyCommandReply.ErrorCode {
				t.Errorf("CopyCommandReply ErrorCode mismatch: got %d, want %d", decoded.CopyCommandReply.ErrorCode, original.CopyCommandReply.ErrorCode)
			}
		}
	}
}

// Test edge cases
func TestEmptyPayloads(t *testing.T) {
	// Test CourierEnvelope with empty payloads
	original := &CourierEnvelope{
		IntermediateReplicas: [2]uint8{0, 0},
		Dek1:                 [60]uint8{},
		Dek2:                 [60]uint8{},
		ReplyIndex:           0,
		Epoch:                0,
		SenderPubkeyLen:      0,
		SenderPubkey:         []uint8{},
		CiphertextLen:        0,
		Ciphertext:           []uint8{},
		IsRead:               0,
	}

	encoded, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to encode empty CourierEnvelope: %v", err)
	}
	decoded := &CourierEnvelope{}
	_, err = decoded.Parse(encoded)
	if err != nil {
		t.Fatalf("Failed to decode empty CourierEnvelope: %v", err)
	}

	if decoded.SenderPubkeyLen != 0 {
		t.Errorf("Expected SenderPubkeyLen to be 0, got %d", decoded.SenderPubkeyLen)
	}
	if decoded.CiphertextLen != 0 {
		t.Errorf("Expected CiphertextLen to be 0, got %d", decoded.CiphertextLen)
	}
}

func TestMaxValues(t *testing.T) {
	// Test with maximum values
	maxSenderPubkey := make([]byte, 65535)    // max uint16
	maxCiphertext := make([]byte, 4294967295) // This would be too large, so use a reasonable size
	// Use a more reasonable size for testing
	maxCiphertext = make([]byte, 1000000) // 1MB

	original := &CourierEnvelope{
		IntermediateReplicas: [2]uint8{255, 255},
		Dek1:                 [60]uint8{},
		Dek2:                 [60]uint8{},
		ReplyIndex:           255,
		Epoch:                18446744073709551615, // max uint64
		SenderPubkeyLen:      uint16(len(maxSenderPubkey)),
		SenderPubkey:         maxSenderPubkey,
		CiphertextLen:        uint32(len(maxCiphertext)),
		Ciphertext:           maxCiphertext,
		IsRead:               255,
	}

	// Fill arrays with max values
	for i := range original.Dek1 {
		original.Dek1[i] = 255
	}
	for i := range original.Dek2 {
		original.Dek2[i] = 255
	}
	for i := range maxSenderPubkey {
		maxSenderPubkey[i] = 255
	}
	for i := range maxCiphertext {
		maxCiphertext[i] = 255
	}

	encoded, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to encode max values CourierEnvelope: %v", err)
	}
	decoded := &CourierEnvelope{}
	_, err = decoded.Parse(encoded)
	if err != nil {
		t.Fatalf("Failed to decode max values CourierEnvelope: %v", err)
	}

	if decoded.Epoch != original.Epoch {
		t.Errorf("Epoch mismatch: got %d, want %d", decoded.Epoch, original.Epoch)
	}
	if decoded.ReplyIndex != original.ReplyIndex {
		t.Errorf(errReplyIndexMismatch, decoded.ReplyIndex, original.ReplyIndex)
	}
}
