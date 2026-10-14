// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
)

const slowWrite = 300 * time.Millisecond

func uploadAllAtOnce(upload func(i int) error) (time.Duration, []error) {
	start := make(chan struct{})
	errs := make([]error, raceUploaders)
	var wg sync.WaitGroup
	for i := range raceUploaders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = upload(i)
		}()
	}
	began := time.Now()
	close(start)
	wg.Wait()
	return time.Since(began), errs
}

func TestSlowDescriptorWriteDoesNotDelayOtherUploads(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	scheme := signschemes.ByName(testSchemeName)
	require.NotNil(t, scheme)
	pks := make([][publicKeyHashSize]byte, raceUploaders)
	mixRaws, replicaRaws := make([][]byte, raceUploaders), make([][]byte, raceUploaders)
	mixes, replicas := make([]*pki.MixDescriptor, raceUploaders), make([]*pki.ReplicaDescriptor, raceUploaders)
	for i := range raceUploaders {
		pub, priv, err := scheme.GenerateKey()
		require.NoError(t, err)
		id, err := pub.MarshalBinary()
		require.NoError(t, err)
		pks[i] = hash.Sum256(id)
		mu := &pki.SignedUpload{MixDescriptor: &pki.MixDescriptor{Name: fmt.Sprintf("mix%d", i), Epoch: epoch, IdentityKey: id}}
		require.NoError(t, mu.Sign(priv, pub))
		mixRaws[i], err = mu.Marshal()
		require.NoError(t, err)
		mixes[i] = mu.MixDescriptor
		ru := &pki.SignedReplicaUpload{ReplicaDescriptor: &pki.ReplicaDescriptor{Name: fmt.Sprintf("replica%d", i), Epoch: epoch, IdentityKey: id}}
		require.NoError(t, ru.Sign(priv, pub))
		replicaRaws[i], err = ru.Marshal()
		require.NoError(t, err)
		replicas[i] = ru.ReplicaDescriptor
	}
	cases := []struct {
		name   string
		bucket string
		upload func(st *state, i int) error
	}{
		{"mix", descriptorsBucket, func(st *state, i int) error { return st.onDescriptorUpload(mixRaws[i], mixes[i], epoch) }},
		{"replica", replicaDescriptorsBucket, func(st *state, i int) error {
			return st.onReplicaDescriptorUpload(replicaRaws[i], replicas[i], epoch)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newRaceState(t)
			st.beforeDescriptorWrite = func() { time.Sleep(slowWrite) }
			took, errs := uploadAllAtOnce(func(i int) error { return tc.upload(st, i) })
			for _, err := range errs {
				require.NoError(t, err)
			}
			require.Less(t, took, 3*slowWrite, "%d uploads, %v per write", raceUploaders, slowWrite)
			for i := range raceUploaders {
				require.NotEmpty(t, storedUpload(t, st, tc.bucket, epoch, pks[i]))
			}
		})
	}
}
