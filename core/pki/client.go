package pki

import (
	"context"

	"github.com/katzenpost/hpqc/sign"

	"github.com/katzenpost/katzenpost/loops"
)

// Client is the read-only PKI consumer interface. It is satisfied by any
// PKI client that retrieves and deserializes consensus documents; it does
// not include any descriptor-upload methods. Use this interface in callers
// that only need to read the PKI (the client daemon, the courier, the
// directory authority's own consumer of historical documents).
type Client interface {
	// GetPKIDocumentForEpoch returns the PKI document along with the raw
	// serialized form for the provided epoch.
	GetPKIDocumentForEpoch(ctx context.Context, epoch uint64) (*Document, []byte, error)

	// Deserialize returns a PKI document given the raw bytes.
	Deserialize(raw []byte) (*Document, error)
}

// PostingClient extends Client with descriptor-upload methods used by
// nodes that publish their own descriptors to the directory authorities,
// such as mix nodes, gateways, service nodes, and pigeonhole storage
// replicas.
type PostingClient interface {
	Client

	// Post posts the node's descriptor to the PKI for the provided epoch.
	Post(ctx context.Context, epoch uint64, signingPrivateKey sign.PrivateKey, signingPublicKey sign.PublicKey, d *MixDescriptor, loopstats *loops.LoopStats) error

	// PostReplica posts the pigeonhole storage replica node's descriptor to the PKI for the provided epoch.
	PostReplica(ctx context.Context, epoch uint64, signingPrivateKey sign.PrivateKey, signingPublicKey sign.PublicKey, d *ReplicaDescriptor) error
}
