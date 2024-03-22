package http_proxy

// Request is the type which is serialized into the cborplugin request payload.
type Request struct {
	// Payload contains the proxied http request
	Payload []byte
}
