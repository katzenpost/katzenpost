package decoy

import (
	"fmt"
	"github.com/katzenpost/hpqc/kem/schemes"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/sphinx/path"
	"github.com/katzenpost/katzenpost/loops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

var testingSchemeName = "xwing"
var testingScheme = schemes.ByName(testingSchemeName)

// Helper function to create a realistic path of hops within the network.
func createPathHops(t *testing.T, numMixes, numProviders int) ([]*sphinx.PathHop, error) {
	require := require.New(t)

	// Generate a realistic PKI document simulating network structure
	epoch, _, _ := epochtime.Now()
	doc, err := generateMixnet(numMixes, numProviders, epoch)
	require.NoError(err, "Failed to generate mixnet for testing")

	// Ensure a provider is available for the test
	require.Greater(len(doc.Providers), 0, "No providers available in the topology")

	// Setup geometric data for packet path calculations
	nike := ecdh.Scheme(rand.Reader)
	geo := geo.GeometryFromUserForwardPayloadLength(nike, 1024, true, 5) // Adjust size as needed

	// Choose source and destination nodes for the path
	src := doc.Topology[0][0]
	dst := doc.Providers[0]

	recipient := []byte("recipient")
	surbID := &[constants.SURBIDLength]byte{}

	// Create a path using Sphinx path generation logic
	path, _, err := path.New(rand.NewMath(), geo, doc, recipient, src, dst, surbID, time.Now(), false, true)
	return path, err
}

// TestIncrementSentSegments ensures that sent segments are counted correctly.
func TestIncrementSentSegments(t *testing.T) {
	d := newTestDecoy()
	path, err := createPathHops(t, 5, 2)
	require.NoError(t, err)

	// Increment sent segments for both forward and reverse paths
	d.incrementSentSegments(path, path)
	require.NotNil(t, path, "Path should not be nil")

	epoch, _, _ := epochtime.Now()
	segments := pathToSegments(path)
	for _, segment := range segments {
		count := d.sentLoops[epoch][segment]
		assert.Equal(t, 2, count, "Each segment should have a count of 2 since path is used for both fwd and rev")
	}
}

// TestIncrementCompleted checks that completed segments are handled correctly.
func TestIncrementCompleted(t *testing.T) {
	d := newTestDecoy()
	path, err := createPathHops(t, 5, 2)
	require.NoError(t, err)

	// Increment completed segments for both forward and reverse paths
	d.incrementCompleted(path, path)

	epoch, _, _ := epochtime.Now()
	segments := pathToSegments(path)
	for _, segment := range segments {
		count := d.completedLoops[epoch][segment]
		assert.Equal(t, 2, count, "Each segment should have a count of 2 since path is used for both fwd and rev")
	}
}

// TestDecoyGarbageCollection ensures that garbage collection is functioning correctly.
func TestDecoyGarbageCollection(t *testing.T) {
	d := newTestDecoy()
	path, err := createPathHops(t, 5, 2)
	require.NoError(t, err)

	// Simulate several epochs of activity
	d.incrementSentSegments(path, path)
	d.incrementCompleted(path, path)

	// Move time forward and trigger garbage collection
	epoch, _, _ := epochtime.Now()
	d.gc(epoch - 7) // simulate passage of 7 epochs

	// Check if old data has been cleaned up
	assert.Empty(t, d.sentLoops[epoch-7], "Old sent loops should be garbage collected")
	assert.Empty(t, d.completedLoops[epoch-7], "Old completed loops should be garbage collected")
}

// NewTestDecoy creates a decoy instance with initialized maps for unit testing.
func newTestDecoy() *decoy {
	return &decoy{
		sentLoops:      make(map[uint64]map[[loops.SegmentIDSize]byte]int),
		completedLoops: make(map[uint64]map[[loops.SegmentIDSize]byte]int),
	}
}

func generateMixnet(numMixes, numProviders int, epoch uint64) (*pki.Document, error) {
	mixes, err := generateNodes(false, numMixes, epoch)
	if err != nil {
		return nil, err
	}
	providers, err := generateNodes(true, numProviders, epoch)
	if err != nil {
		return nil, err
	}
	pdescs := make([]*pki.MixDescriptor, len(providers))
	for i, p := range providers {
		pdescs[i] = p
	}
	topology := generateRandomTopology(mixes, 3)

	sharedRandomCommit := make(map[[pki.PublicKeyHashSize]byte][]byte)
	doc := &pki.Document{
		Version:            pki.DocumentVersion,
		Epoch:              epoch,
		GenesisEpoch:       epoch,
		Mu:                 0.25,
		MuMaxDelay:         4000,
		LambdaP:            1.2,
		LambdaPMaxDelay:    300,
		Topology:           topology,
		Providers:          pdescs,
		SharedRandomCommit: sharedRandomCommit,
		SharedRandomValue:  make([]byte, pki.SharedRandomValueLength),
	}
	return doc, nil
}

func generateNodes(isProvider bool, num int, epoch uint64) ([]*pki.MixDescriptor, error) {
	mixes := []*pki.MixDescriptor{}
	for i := 0; i < num; i++ {
		mixIdentityPublicKey, _, err := cert.Scheme.GenerateKey()
		if err != nil {
			return nil, err
		}
		mixKeys, err := generateMixKeys(epoch)
		if err != nil {
			return nil, err
		}
		var name string
		if isProvider {
			name = fmt.Sprintf("NSA_Spy_Satelite_Provider%d", i)
		} else {
			name = fmt.Sprintf("NSA_Spy_Satelite_Mix%d", i)
		}

		scheme := testingScheme
		linkPubKey, _, err := scheme.GenerateKeyPair()
		if err != nil {
			return nil, err
		}

		linkKeyBlob, err := linkPubKey.MarshalBinary()
		if err != nil {
			return nil, err
		}

		blob, err := mixIdentityPublicKey.MarshalBinary()
		if err != nil {
			return nil, err
		}

		mix := &pki.MixDescriptor{
			Name:        name,
			Epoch:       epoch,
			IdentityKey: blob,
			LinkKey:     linkKeyBlob,
			MixKeys:     mixKeys,
			Addresses: map[pki.Transport][]string{
				pki.Transport("tcp4"): []string{fmt.Sprintf("127.0.0.1:%d", i+1)},
			},
			Kaetzchen:  nil,
			Provider:   isProvider,
			LoadWeight: 0,
		}
		mixes = append(mixes, mix)
	}
	return mixes, nil
}

func generateRandomTopology(nodes []*pki.MixDescriptor, layers int) [][]*pki.MixDescriptor {
	rng := rand.NewMath()
	nodeIndexes := rng.Perm(len(nodes))
	topology := make([][]*pki.MixDescriptor, layers)
	for idx, layer := 0, 0; idx < len(nodes); idx++ {
		n := nodes[nodeIndexes[idx]]
		topology[layer] = append(topology[layer], n)
		layer++
		layer = layer % len(topology)
	}
	return topology
}

func generateMixKeys(epoch uint64) (map[uint64][]byte, error) {
	m := make(map[uint64][]byte)
	for i := epoch; i < epoch+3; i++ {
		publickey, _, err := ecdh.Scheme(rand.Reader).GenerateKeyPairFromEntropy(rand.Reader)
		if err != nil {
			return nil, err
		}
		m[uint64(i)] = publickey.Bytes()
	}
	return m, nil
}
