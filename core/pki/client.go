package pki

import (
	"context"

	"github.com/katzenpost/hpqc/sign"
)

// Client is the abstract interface used for PKI interaction.
type Client interface {
	// Get returns the PKI document along with the raw serialized form for the provided epoch.
	Get(ctx context.Context, epoch uint64) (*Document, []byte, error)

	// Post posts the node's descriptor to the PKI for the provided epoch.
	Post(ctx context.Context, epoch uint64, signingPrivateKey sign.PrivateKey, signingPublicKey sign.PublicKey, d *MixDescriptor) error

	// Deserialize returns PKI document given the raw bytes.
	Deserialize(raw []byte) (*Document, error)
}
