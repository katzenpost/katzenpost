package client2

type Response struct {
	ID      int    `cbor:id`
	Payload []byte `cbor:answer`
}

type Request struct {
	ID        int    `cbor:id`
	Operation []byte `cbor:operation`
	Payload   []byte `cbor:payload`
}
