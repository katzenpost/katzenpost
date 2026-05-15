package pki

import (
	"context"

	"github.com/katzenpost/hpqc/sign"

	"github.com/katzenpost/katzenpost/loops"
)

// Fetcher retrieves a PKI document for a given epoch from a remote
// authority. The returned raw bytes are the same byte sequence that
// would be passed to Deserializer.Deserialize for verification against
// a configured trust anchor.
type Fetcher interface {
	GetPKIDocumentForEpoch(ctx context.Context, epoch uint64) (*Document, []byte, error)
}

// Deserializer verifies the given raw bytes against the configured
// directory authority public keys and returns the parsed Document.
// Implementations carry the verifier set internally so that callers
// cannot accidentally parse an unverified document.
type Deserializer interface {
	Deserialize(raw []byte) (*Document, error)
}

// MixDescriptorPoster posts the node's own MixDescriptor to the
// directory authorities. Used by mix, gateway, and service nodes.
type MixDescriptorPoster interface {
	Post(ctx context.Context, epoch uint64, signingPrivateKey sign.PrivateKey, signingPublicKey sign.PublicKey, d *MixDescriptor, loopstats *loops.LoopStats) error
}

// ReplicaDescriptorPoster posts the node's own ReplicaDescriptor to the
// directory authorities. Used by pigeonhole storage replicas.
type ReplicaDescriptorPoster interface {
	PostReplica(ctx context.Context, epoch uint64, signingPrivateKey sign.PrivateKey, signingPublicKey sign.PublicKey, d *ReplicaDescriptor) error
}

// MixNodeClient is the PKI surface used by mix, gateway, and service
// nodes: fetch consensus documents and post the node's own
// MixDescriptor.
type MixNodeClient interface {
	Fetcher
	MixDescriptorPoster
}

// ReplicaNodeClient is the PKI surface used by pigeonhole storage
// replicas: fetch consensus documents and post the replica's own
// ReplicaDescriptor.
type ReplicaNodeClient interface {
	Fetcher
	ReplicaDescriptorPoster
}

// PostingClient is the full PKI surface implemented by the voting
// authority client: fetch consensus documents, deserialize foreign
// byte streams against configured trust anchors, and post both kinds
// of descriptor. Concrete implementations that satisfy every PKI
// role declare themselves against this interface.
type PostingClient interface {
	Fetcher
	Deserializer
	MixDescriptorPoster
	ReplicaDescriptorPoster
}
