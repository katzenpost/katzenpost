// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/linxGnu/grocksdb"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/pigeonhole"
)

func TestEpochPrefixOrdering(t *testing.T) {
	for ep := uint64(0); ep < 16; ep++ {
		cur := epochPrefix(ep)
		next := epochPrefix(ep + 1)
		require.Len(t, cur, keyEpochSize)
		require.Len(t, next, keyEpochSize)
		require.Negative(t, bytes.Compare(cur, next),
			"epochPrefix(%d) must sort before epochPrefix(%d)", ep, ep+1)
		require.Equal(t, ep, binary.BigEndian.Uint64(cur))
	}
}

func TestKeptEpochs(t *testing.T) {
	require.Equal(t, []uint64{0}, keptEpochs(0))
	require.Equal(t, []uint64{1, 0}, keptEpochs(1))
	require.Equal(t, []uint64{42, 41}, keptEpochs(42))
}

// putRawBox writes a Box blob directly at the given replica epoch,
// bypassing the existence check in handleReplicaWrite. Useful for
// staging records that look as though they were stored in an earlier
// week.
func putRawBox(t *testing.T, st *state, epoch uint64, boxID [bacap.BoxIDSize]byte, payload []byte, sig [bacap.SignatureSize]byte) {
	t.Helper()
	box := &pigeonhole.Box{
		BoxID:      boxID,
		PayloadLen: uint32(len(payload)),
		Payload:    payload,
		Signature:  sig,
	}
	wo := grocksdb.NewDefaultWriteOptions()
	defer wo.Destroy()
	require.NoError(t, st.db.Put(wo, boxKey(epoch, boxID[:]), box.Bytes()))
}

func boxPresent(t *testing.T, st *state, epoch uint64, boxID [bacap.BoxIDSize]byte) bool {
	t.Helper()
	ro := grocksdb.NewDefaultReadOptions()
	defer ro.Destroy()
	v, err := st.db.Get(ro, boxKey(epoch, boxID[:]))
	require.NoError(t, err)
	defer v.Free()
	return v.Size() > 0
}

func TestWipeStaleBoxes(t *testing.T) {
	st := setupImmutabilityTestState(t)
	cur := currentReplicaEpoch()
	require.GreaterOrEqual(t, cur, uint64(3),
		"test requires the replica epoch counter to be at least 3")

	var boxID [bacap.BoxIDSize]byte
	_, err := rand.Reader.Read(boxID[:])
	require.NoError(t, err)
	var sig [bacap.SignatureSize]byte
	_, err = rand.Reader.Read(sig[:])
	require.NoError(t, err)

	for _, ep := range []uint64{cur, cur - 1, cur - 2, cur - 3} {
		putRawBox(t, st, ep, boxID, []byte("kept-or-wiped"), sig)
	}

	require.NoError(t, st.WipeStaleBoxes())

	require.True(t, boxPresent(t, st, cur, boxID),
		"current epoch must survive the wipe")
	require.True(t, boxPresent(t, st, cur-1, boxID),
		"previous epoch must survive the wipe")
	require.False(t, boxPresent(t, st, cur-2, boxID),
		"two epochs ago must be wiped")
	require.False(t, boxPresent(t, st, cur-3, boxID),
		"three epochs ago must be wiped")
}

func TestStateReadFallbackToPreviousEpoch(t *testing.T) {
	st := setupImmutabilityTestState(t)
	cur := currentReplicaEpoch()
	require.GreaterOrEqual(t, cur, uint64(1))

	var boxID [bacap.BoxIDSize]byte
	_, err := rand.Reader.Read(boxID[:])
	require.NoError(t, err)
	var sig [bacap.SignatureSize]byte
	_, err = rand.Reader.Read(sig[:])
	require.NoError(t, err)
	payload := []byte("from-the-prior-week")

	putRawBox(t, st, cur-1, boxID, payload, sig)

	got, err := st.stateHandleReplicaRead(&pigeonhole.ReplicaRead{BoxID: boxID})
	require.NoError(t, err)
	require.Equal(t, payload, got.Payload)
	require.Equal(t, sig, got.Signature)
}

func TestTombstoneShadowsPriorEpochBox(t *testing.T) {
	st := setupImmutabilityTestState(t)
	cur := currentReplicaEpoch()
	require.GreaterOrEqual(t, cur, uint64(1))

	var boxID [bacap.BoxIDSize]byte
	_, err := rand.Reader.Read(boxID[:])
	require.NoError(t, err)
	var origSig [bacap.SignatureSize]byte
	_, err = rand.Reader.Read(origSig[:])
	require.NoError(t, err)

	putRawBox(t, st, cur-1, boxID, []byte("the-original-payload"), origSig)

	var tombSig [bacap.SignatureSize]byte
	_, err = rand.Reader.Read(tombSig[:])
	require.NoError(t, err)
	require.NoError(t, st.handleReplicaTombstone(boxID, tombSig))

	got, err := st.stateHandleReplicaRead(&pigeonhole.ReplicaRead{BoxID: boxID})
	require.NoError(t, err)
	require.Empty(t, got.Payload,
		"tombstone written at the current epoch must shadow a prior-epoch box")
	require.Equal(t, tombSig, got.Signature)
}

func TestWriteIdempotentAcrossEpochs(t *testing.T) {
	st := setupImmutabilityTestState(t)
	cur := currentReplicaEpoch()
	require.GreaterOrEqual(t, cur, uint64(1))

	var boxID [bacap.BoxIDSize]byte
	_, err := rand.Reader.Read(boxID[:])
	require.NoError(t, err)
	var sig [bacap.SignatureSize]byte
	_, err = rand.Reader.Read(sig[:])
	require.NoError(t, err)
	payload := []byte("identical-content")

	putRawBox(t, st, cur-1, boxID, payload, sig)

	bid := boxID
	sg := sig
	cmd := &commands.ReplicaWrite{
		BoxID:     &bid,
		Signature: &sg,
		Payload:   payload,
	}
	require.NoError(t, st.handleReplicaWrite(cmd),
		"a retry whose bytes match the prior-epoch record must be idempotent")
	require.False(t, boxPresent(t, st, cur, boxID),
		"an idempotent retry must not write a fresh copy at the current epoch")
}

func TestWriteRejectedAcrossEpochs(t *testing.T) {
	st := setupImmutabilityTestState(t)
	cur := currentReplicaEpoch()
	require.GreaterOrEqual(t, cur, uint64(1))

	var boxID [bacap.BoxIDSize]byte
	_, err := rand.Reader.Read(boxID[:])
	require.NoError(t, err)
	var origSig [bacap.SignatureSize]byte
	_, err = rand.Reader.Read(origSig[:])
	require.NoError(t, err)

	putRawBox(t, st, cur-1, boxID, []byte("prior"), origSig)

	var newSig [bacap.SignatureSize]byte
	_, err = rand.Reader.Read(newSig[:])
	require.NoError(t, err)
	bid := boxID
	cmd := &commands.ReplicaWrite{
		BoxID:     &bid,
		Signature: &newSig,
		Payload:   []byte("different"),
	}
	err = st.handleReplicaWrite(cmd)
	require.ErrorIs(t, err, ErrBoxAlreadyExists,
		"a write differing from the prior-epoch record must be rejected")
}
