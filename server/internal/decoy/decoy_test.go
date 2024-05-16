package decoy

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
)

var testingSchemeName = "xwing"
var testingScheme = schemes.ByName(testingSchemeName)

func TestIncrementSentSegments(t *testing.T) {
	d := newTestDecoy()
	fwdPath, revPath, err := createPaths(5, 2)
	require.NoError(t, err, "failed to create paths")

	// Increment sent segments
	d.incrementSentSegments(fwdPath, revPath)

	epoch, _, _ := epochtime.Now()
	// Check both forward and reverse paths
	checkSegments(t, d.sentLoops[epoch], fwdPath, revPath, "sent")
}

func TestIncrementSentAndCompletedSegments(t *testing.T) {
	d := newTestDecoy()
	fwdPath, revPath, err := createPaths(5, 2)
	require.NoError(t, err, "failed to create paths")

	// Increment sent and completed segments
	d.incrementSentSegments(fwdPath, revPath)
	d.incrementCompleted(fwdPath, revPath)

	epoch, _, _ := epochtime.Now()
	// Check both forward and reverse paths
	checkSegments(t, d.sentLoops[epoch], fwdPath, revPath, "sent")
	checkSegments(t, d.completedLoops[epoch], fwdPath, revPath, "completed")
}

func TestIncrementCompletedSegments(t *testing.T) {
	d := newTestDecoy()
	fwdPath, revPath, err := createPaths(5, 2)
	require.NoError(t, err, "failed to create paths")

	// Increment completed segments
	d.incrementCompleted(fwdPath, revPath)

	epoch, _, _ := epochtime.Now()
	// Verify both forward and reverse paths
	checkSegments(t, d.completedLoops[epoch], fwdPath, revPath, "completed")
}

// TestDecoyGarbageCollection ensures that garbage collection is functioning correctly.
func TestDecoyGarbageCollection(t *testing.T) {
	d := newTestDecoy()
	fwdPath, revPath, err := createPaths(5, 2)
	require.NoError(t, err, "failed to create paths")

	// Simulate traffic and completion for paths
	d.incrementSentSegments(fwdPath, revPath)
	d.incrementCompleted(fwdPath, revPath)

	currentEpoch, _, _ := epochtime.Now()
	// Force garbage collection for past epochs
	for pastEpoch := currentEpoch - 10; pastEpoch <= currentEpoch; pastEpoch++ {
		d.gc(pastEpoch - 7) // Collect data older than 7 epochs
	}

	// Assert that old epochs have been cleaned up
	for pastEpoch := currentEpoch - 10; pastEpoch <= currentEpoch-7; pastEpoch++ {
		assert.Empty(t, d.sentLoops[pastEpoch], "Old sent loops should be cleaned up")
		assert.Empty(t, d.completedLoops[pastEpoch], "Old completed loops should be cleaned up")
	}
}

// NewTestDecoy creates a decoy instance with initialized maps for unit testing.
func newTestDecoy() *decoy {
	return &decoy{
		sentLoops:      make(map[uint64]map[[loops.SegmentIDSize]byte]int),
		completedLoops: make(map[uint64]map[[loops.SegmentIDSize]byte]int),
	}
}

func checkSegments(t *testing.T, data map[[loops.SegmentIDSize]byte]int, fwdPath, revPath []*sphinx.PathHop, label string) {
	fwdSegments := pathToSegments(fwdPath)
	revSegments := pathToSegments(revPath)

	for _, segment := range fwdSegments {
		count, exists := data[segment]
		require.True(t, exists, fmt.Sprintf("Segment should exist in %s loops: %v", label, segment))
		assert.Equal(t, 1, count, fmt.Sprintf("Forward segment should have a count of 1 in %s", label))
	}

	for _, segment := range revSegments {
		count, exists := data[segment]
		require.True(t, exists, fmt.Sprintf("Segment should exist in %s loops: %v", label, segment))
		assert.Equal(t, 1, count, fmt.Sprintf("Reverse segment should have a count of 1 in %s", label))
	}
}

func createPaths(numMixes, numProviders int) ([]*sphinx.PathHop, []*sphinx.PathHop, error) {
	epoch, _, _ := epochtime.Now()
	doc, err := generateMixnet(numMixes, numProviders, numProviders, epoch)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate mixnet for testing: %w", err)
	}
	if len(doc.ServiceNodes) == 0 {
		return nil, nil, fmt.Errorf("no service nodes available in the topology")
	}
	if len(doc.GatewayNodes) == 0 {
		return nil, nil, fmt.Errorf("no gateway nodes available in the topology")
	}

	nike := ecdh.Scheme(rand.Reader)
	geo := geo.GeometryFromUserForwardPayloadLength(nike, 1024, true, 5)

	src := doc.Topology[0][0]
	dst := doc.ServiceNodes[0]

	recipient := []byte("recipient")
	surbID := &[constants.SURBIDLength]byte{}

	// Create forward path
	fwdPath, _, err := path.New(rand.NewMath(), geo, doc, recipient, src, dst, surbID, time.Now(), false, true)
	if err != nil {
		return nil, nil, err
	}

	// Create reverse path
	revPath, _, err := path.New(rand.NewMath(), geo, doc, recipient, dst, src, surbID, time.Now(), false, false)
	if err != nil {
		return nil, nil, err
	}

	return fwdPath, revPath, nil
}

func generateMixnet(numMixes, numServiceNodes, numGatewayNodes int, epoch uint64) (*pki.Document, error) {
	mixes, err := generateNodes(false, false, numMixes, epoch)
	if err != nil {
		return nil, err
	}
	serviceNodes, err := generateNodes(false, true, numServiceNodes, epoch)
	if err != nil {
		return nil, err
	}
	gatewayNodes, err := generateNodes(true, false, numGatewayNodes, epoch)
	if err != nil {
		return nil, err
	}

	serviceNodeDescs := make([]*pki.MixDescriptor, len(serviceNodes))
	for i, p := range serviceNodes {
		serviceNodeDescs[i] = p
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
		ServiceNodes:       serviceNodeDescs,
		GatewayNodes:       gatewayNodes,
		SharedRandomCommit: sharedRandomCommit,
		SharedRandomValue:  make([]byte, pki.SharedRandomValueLength),
	}
	return doc, nil
}

func generateNodes(isGatewayNode, isServiceNode bool, num int, epoch uint64) ([]*pki.MixDescriptor, error) {
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
		if isServiceNode {
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
			Kaetzchen:     nil,
			IsServiceNode: isServiceNode,
			IsGatewayNode: isGatewayNode,
			LoadWeight:    0,
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
