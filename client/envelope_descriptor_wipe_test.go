// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package client

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/pigeonhole"
)

func trackDescriptorARQ(d *Daemon, appID *[AppIDLength]byte, n byte) *ARQMessage {
	surbID := &[sphinxConstants.SURBIDLength]byte{n}
	envHash := &[32]byte{n}
	m := &ARQMessage{
		AppID:              appID,
		QueryID:            &[thin.QueryIDLength]byte{n},
		SURBID:             surbID,
		EnvelopeHash:       envHash,
		EnvelopeDescriptor: bytes.Repeat([]byte{0xa7}, 64),
	}
	d.replyLock.Lock()
	d.arqSurbIDMap[*surbID] = m
	if d.arqEnvelopeHashMap != nil {
		d.arqEnvelopeHashMap[*envHash] = surbID
	}
	d.replyLock.Unlock()
	return m
}

func TestCompletedARQWipesEnvelopeDescriptor(t *testing.T) {
	d, appID, responseCh := setupDaemonWithMockConn(t)
	m := trackDescriptorARQ(d, appID, 1)

	d.handlePayloadReply(m, &pigeonhole.CourierEnvelopeReply{Payload: make([]byte, 128)}, nil)
	resp := waitForResponse(t, responseCh)
	require.NotNil(t, resp.StartResendingEncryptedMessageReply)
	require.Empty(t, d.arqSurbIDMap)

	requireSURBKeyWiped(t, m.EnvelopeDescriptor, "envelope descriptor left in memory after its ARQ completed")
}

func TestCancelledARQWipesEnvelopeDescriptor(t *testing.T) {
	d, appID, responseCh := setupDaemonWithMockConn(t)
	m := trackDescriptorARQ(d, appID, 2)

	d.cancelResendingEncryptedMessage(&Request{
		AppID: appID,
		CancelResendingEncryptedMessage: &thin.CancelResendingEncryptedMessage{
			QueryID:      &[thin.QueryIDLength]byte{9},
			EnvelopeHash: m.EnvelopeHash,
		},
	})
	waitForResponse(t, responseCh)
	waitForResponse(t, responseCh)

	requireSURBKeyWiped(t, m.EnvelopeDescriptor, "envelope descriptor left in memory after its ARQ was cancelled")
}

func TestCleanupForAppIDWipesEnvelopeDescriptor(t *testing.T) {
	d := newTestDaemonState(t)
	appID := &[AppIDLength]byte{7}
	m := trackDescriptorARQ(d, appID, 3)

	d.cleanupForAppID(appID)

	requireSURBKeyWiped(t, m.EnvelopeDescriptor, "envelope descriptor left in memory after cleanupForAppID")
}

func TestDroppedARQResendWipesEnvelopeDescriptor(t *testing.T) {
	d := newTestDaemonState(t)
	m := trackDescriptorARQ(d, &[AppIDLength]byte{}, 4)

	d.arqDoResend(m.SURBID)

	require.Empty(t, d.arqSurbIDMap)
	requireSURBKeyWiped(t, m.EnvelopeDescriptor, "envelope descriptor left in memory after the resend dropped its ARQ")
}

func TestRejectedStartResendingWipesEnvelopeDescriptor(t *testing.T) {
	d, appID, responseCh := setupDaemonWithMockConn(t)
	desc := bytes.Repeat([]byte{0xa8}, 64)

	d.startResendingEncryptedMessage(&Request{
		AppID: appID,
		StartResendingEncryptedMessage: &thin.StartResendingEncryptedMessage{
			EnvelopeHash:       &[32]byte{5},
			MessageCiphertext:  []byte("ciphertext"),
			EnvelopeDescriptor: desc,
		},
	})
	resp := waitForResponse(t, responseCh)
	require.Equal(t, thin.ThinClientErrorInvalidRequest, resp.StartResendingEncryptedMessageReply.ErrorCode)

	requireSURBKeyWiped(t, desc, "envelope descriptor left in memory after StartResendingEncryptedMessage was refused")
}

func TestShutdownWipesEnvelopeDescriptors(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)
	port, err := getFreePort()
	require.NoError(t, err)
	cfg.Listen.Tcp.Address = fmt.Sprintf("localhost:%d", port)

	d, err := NewDaemon(cfg)
	require.NoError(t, err)
	require.NoError(t, d.Start())
	m := trackDescriptorARQ(d, &[AppIDLength]byte{}, 6)

	d.Shutdown()

	d.replyLock.Lock()
	defer d.replyLock.Unlock()
	requireSURBKeyWiped(t, m.EnvelopeDescriptor, "envelope descriptor left in memory after Shutdown")
}
