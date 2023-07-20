package client2

type Response struct {
	// AppID must be a unique identity for the client application
	// that is receiving this Response.
	AppID int `cbor:id`

	// Payload contains the Response payload, a SURB reply.
	Payload []byte `cbor:payload`
}

type Request struct {
	// AppID must be a unique identity for the client application
	// that is sending this Request.
	AppID int `cbor:id`

	// DestinationIdHash is 32 byte hash of the destination's
	// identity public key.
	DestinationIdHash *[32]byte `cbor:destination_id_hash`

	// RecipientQueueID is the queue identity which will receive the message.
	RecipientQueueID []byte `cbor:recipient_queue_id`

	// Payload is the actual Sphinx packet.
	Payload []byte `cbor:payload`

	// IsSendOp is set to true if the intent is to send a message through
	// the mix network.
	IsSendOp bool `cbor:is_send_op`

	// IsEchoOp is set to true if the intent is to merely test that the unix
	// socket listener is working properly; the Response payload will be
	// contain the Request payload.
	IsEchoOp bool `cbor:is_echo_op`

	// IsLoopDecoy is set to true to indicate that this message shall
	// be a loop decoy message.
	IsLoopDecoy bool `cbor:is_loop_decoy`

	// IsDropDecoy is set to true to indicate that this message shall
	// be a drop decoy message.
	IsDropDecoy bool `cbor:is_drop_decoy`
}
