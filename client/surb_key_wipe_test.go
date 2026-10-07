// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package client

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/thin"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

func requireSURBKeyWiped(t *testing.T, key []byte, msg string) {
	t.Helper()
	require.Equal(t, make([]byte, len(key)), key, msg)
}

func TestGCWipesExpiredSURBKeys(t *testing.T) {
	d, _, _, _, _ := setupFullClient(t)
	d.ingressCh = make(chan *sphinxReply, 10)
	d.gcSurbIDCh = make(chan *[sphinxConstants.SURBIDLength]byte, 10)
	d.gcReplyCh = make(chan *gcReply, 10)
	go d.ingressWorker()
	t.Cleanup(func() { d.Halt() })

	replyID := &[sphinxConstants.SURBIDLength]byte{1}
	decoyID := &[sphinxConstants.SURBIDLength]byte{2}
	replyKey := bytes.Repeat([]byte{0xa1}, 32)
	decoyKey := bytes.Repeat([]byte{0xa2}, 32)
	d.replyLock.Lock()
	d.replies[*replyID] = replyDescriptor{appID: &[AppIDLength]byte{}, surbKey: replyKey}
	d.decoys[*decoyID] = replyDescriptor{appID: &[AppIDLength]byte{}, surbKey: decoyKey}
	d.replyLock.Unlock()

	d.gcSurbIDCh <- replyID
	d.gcSurbIDCh <- decoyID
	require.Eventually(t, func() bool {
		d.replyLock.Lock()
		defer d.replyLock.Unlock()
		return len(d.replies) == 0 && len(d.decoys) == 0
	}, 5*time.Second, 10*time.Millisecond)

	d.replyLock.Lock()
	defer d.replyLock.Unlock()
	requireSURBKeyWiped(t, replyKey, "reply SURB key left in memory after its GC")
	requireSURBKeyWiped(t, decoyKey, "decoy SURB key left in memory after its GC")
}

func TestCleanupForAppIDWipesSURBKeys(t *testing.T) {
	d := newTestDaemonState(t)
	appID := &[AppIDLength]byte{7}
	replyKey := bytes.Repeat([]byte{0xb1}, 32)
	decoyKey := bytes.Repeat([]byte{0xb2}, 32)
	arqKey := bytes.Repeat([]byte{0xb3}, 32)
	arqSurbID := &[sphinxConstants.SURBIDLength]byte{3}

	d.replies[[sphinxConstants.SURBIDLength]byte{1}] = replyDescriptor{appID: appID, surbKey: replyKey}
	d.decoys[[sphinxConstants.SURBIDLength]byte{2}] = replyDescriptor{appID: appID, surbKey: decoyKey}
	d.arqSurbIDMap[*arqSurbID] = &ARQMessage{AppID: appID, SURBID: arqSurbID, SURBDecryptionKeys: arqKey}

	d.cleanupForAppID(appID)

	requireSURBKeyWiped(t, replyKey, "reply SURB key left in memory after cleanupForAppID")
	requireSURBKeyWiped(t, decoyKey, "decoy SURB key left in memory after cleanupForAppID")
	requireSURBKeyWiped(t, arqKey, "ARQ SURB key left in memory after cleanupForAppID")
}

func TestRotateARQSurbIDWipesReplacedSURBKey(t *testing.T) {
	d := newTestDaemonState(t)
	oldKey := bytes.Repeat([]byte{0xc1}, 32)
	newKey := bytes.Repeat([]byte{0xc2}, 32)
	arqMessage := &ARQMessage{SURBID: &[sphinxConstants.SURBIDLength]byte{1}, SURBDecryptionKeys: oldKey}
	d.arqSurbIDMap[*arqMessage.SURBID] = arqMessage

	d.replyLock.Lock()
	d.rotateARQSurbIDLocked(arqMessage, &[sphinxConstants.SURBIDLength]byte{2}, newKey, time.Second)
	d.replyLock.Unlock()

	requireSURBKeyWiped(t, oldKey, "replaced ARQ SURB key left in memory after a resend")
	require.Equal(t, bytes.Repeat([]byte{0xc2}, 32), arqMessage.SURBDecryptionKeys)
}

func TestCancelResendingWipesSURBKeys(t *testing.T) {
	d, appID, responseCh := setupDaemonWithMockConn(t)

	envHash := &[32]byte{1}
	encKey := bytes.Repeat([]byte{0xd1}, 32)
	encSurbID := &[sphinxConstants.SURBIDLength]byte{1}
	d.arqSurbIDMap[*encSurbID] = &ARQMessage{AppID: appID, QueryID: &[thin.QueryIDLength]byte{3}, SURBID: encSurbID, EnvelopeHash: envHash, SURBDecryptionKeys: encKey}
	d.arqEnvelopeHashMap[*envHash] = encSurbID

	writeCapHash := &[32]byte{2}
	copyKey := bytes.Repeat([]byte{0xd2}, 32)
	copySurbID := &[sphinxConstants.SURBIDLength]byte{2}
	d.arqSurbIDMap[*copySurbID] = &ARQMessage{AppID: appID, QueryID: &[thin.QueryIDLength]byte{4}, SURBID: copySurbID, EnvelopeHash: writeCapHash, SURBDecryptionKeys: copyKey}
	d.arqEnvelopeHashMap[*writeCapHash] = copySurbID

	d.cancelResendingEncryptedMessage(&Request{
		AppID: appID,
		CancelResendingEncryptedMessage: &thin.CancelResendingEncryptedMessage{
			QueryID:      &[thin.QueryIDLength]byte{1},
			EnvelopeHash: envHash,
		},
	})
	d.cancelResendingCopyCommand(&Request{
		AppID: appID,
		CancelResendingCopyCommand: &thin.CancelResendingCopyCommand{
			QueryID:      &[thin.QueryIDLength]byte{2},
			WriteCapHash: writeCapHash,
		},
	})
	for i := 0; i < 4; i++ {
		select {
		case <-responseCh:
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for the cancel reply")
		}
	}

	requireSURBKeyWiped(t, encKey, "SURB key left in memory after CancelResendingEncryptedMessage")
	requireSURBKeyWiped(t, copyKey, "SURB key left in memory after CancelResendingCopyCommand")
}

func TestARQResendWithoutListenerWipesSURBKey(t *testing.T) {
	d := newTestDaemonState(t)
	key := bytes.Repeat([]byte{0xe1}, 32)
	surbID := &[sphinxConstants.SURBIDLength]byte{1}
	d.arqSurbIDMap[*surbID] = &ARQMessage{SURBID: surbID, SURBDecryptionKeys: key}

	d.arqDoResend(surbID)

	require.Empty(t, d.arqSurbIDMap)
	requireSURBKeyWiped(t, key, "SURB key left in memory after the resend dropped its message")
}
