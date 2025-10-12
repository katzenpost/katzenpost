package pki

import (
	"context"

	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/katzenpost/loops"
)

// Client is the abstract interface used for PKI interaction.
type Client interface {
	// Get returns the PKI document along with the raw serialized form for the provided epoch.
	GetPKIDocumentForEpoch(ctx context.Context, epoch uint64) (*Document, []byte, error)

	// Post posts the node's descriptor to the PKI for the provided epoch.
	Post(ctx context.Context, epoch uint64, signingPrivateKey sign.PrivateKey, signingPublicKey sign.PublicKey, d *MixDescriptor, loopstats *loops.LoopStats) error

	// PostReplica posts the pigeonhole storage replica node's descriptor to the PKI for the provided epoch.
	PostReplica(ctx context.Context, epoch uint64, signingPrivateKey sign.PrivateKey, signingPublicKey sign.PublicKey, d *ReplicaDescriptor) error

	// Deserialize returns PKI document given the raw bytes.
	Deserialize(raw []byte) (*Document, error)
}
