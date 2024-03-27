package http_proxy

// Request is the type which is serialized into the cborplugin request payload.
type Request struct {
	// Payload contains the proxied http request
	Payload []byte
}

// Response is the type which is serialized and sent as a response from the cborplugin.
type Response struct {
	// Payload contains the entire proxied http response or response chunk.
	Payload []byte

	// ChunkNum indicates which chunk this is.
	ChunkNum uint

	// ChunksTotal is the total number of chunks needed to coalesce the entire http response.
	ChunksTotal uint
}
