package constants

var (
	// PIGEONHOLE_CTX is the cryptographic context used for the pigeonhole storage system.
	PIGEONHOLE_CTX = []byte("pigeonhole context")
)

// CourierServiceName is the name of the courier service.
// It is used to find the courier service in the PKI document.
// Tecnically, it is the recipied queue ID of our Sphinx packets
// which use the Recipient Sphinx routing command for the last hop
// to specify the recipient queue ID.
const CourierServiceName = "courier"
