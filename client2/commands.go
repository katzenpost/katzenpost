package client2

type Response struct {
	ID      int    `cbor:id`
	Payload []byte `cbor:payload`
}

type Request struct {
	// ID must be a unique identity for the request.
	ID int `cbor:id`

	// DestinationIdHash is 32 byte hash of the destination's
	// identity public key.
	DestinationIdHash []byte `cbor:destination_id_hash`

	// RecipientQueueID is the queue identity which will receive the message.
	RecipientQueueID []byte `cbor:recipient_queue_id`

	Payload []byte `cbor:payload`

	IsSendOp bool `cbor:is_send_op`
	IsEchoOp bool `cbor:is_echo_op`
}
