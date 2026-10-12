// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package client

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client/thin"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

type notReadyHandler struct {
	name string
	run  func(d *Daemon, appID *[AppIDLength]byte, writeCap *bacap.WriteCap)
	code func(*Response) uint8
}

var envelopeBuildingHandlers = []notReadyHandler{
	{
		name: "encryptRead",
		run: func(d *Daemon, appID *[AppIDLength]byte, writeCap *bacap.WriteCap) {
			d.encryptRead(&Request{AppID: appID, EncryptRead: &thin.EncryptRead{
				QueryID:         new([thin.QueryIDLength]byte),
				ReadCap:         writeCap.ReadCap(),
				MessageBoxIndex: writeCap.GetMessageBoxIndex(),
			}})
		},
		code: func(r *Response) uint8 { return r.EncryptReadReply.ErrorCode },
	},
	{
		name: "encryptWrite",
		run: func(d *Daemon, appID *[AppIDLength]byte, writeCap *bacap.WriteCap) {
			d.encryptWrite(&Request{AppID: appID, EncryptWrite: &thin.EncryptWrite{
				QueryID:         new([thin.QueryIDLength]byte),
				WriteCap:        writeCap,
				MessageBoxIndex: writeCap.GetMessageBoxIndex(),
				Plaintext:       []byte("hello"),
			}})
		},
		code: func(r *Response) uint8 { return r.EncryptWriteReply.ErrorCode },
	},
	{
		name: "createCourierEnvelopesFromPayload",
		run: func(d *Daemon, appID *[AppIDLength]byte, writeCap *bacap.WriteCap) {
			d.createCourierEnvelopesFromPayload(&Request{AppID: appID, CreateCourierEnvelopesFromPayload: &thin.CreateCourierEnvelopesFromPayload{
				QueryID:        new([thin.QueryIDLength]byte),
				Payload:        []byte("hello"),
				DestWriteCap:   writeCap,
				DestStartIndex: writeCap.GetMessageBoxIndex(),
				IsStart:        true,
				IsLast:         true,
			}})
		},
		code: func(r *Response) uint8 { return r.CreateCourierEnvelopesFromPayloadReply.ErrorCode },
	},
	{
		name: "createCourierEnvelopesFromPayloads",
		run: func(d *Daemon, appID *[AppIDLength]byte, writeCap *bacap.WriteCap) {
			d.createCourierEnvelopesFromPayloads(&Request{AppID: appID, CreateCourierEnvelopesFromPayloads: &thin.CreateCourierEnvelopesFromPayloads{
				QueryID: new([thin.QueryIDLength]byte),
				Destinations: []thin.DestinationPayload{{
					Payload:    []byte("hello"),
					WriteCap:   writeCap,
					StartIndex: writeCap.GetMessageBoxIndex(),
				}},
				IsStart: true,
				IsLast:  true,
			}})
		},
		code: func(r *Response) uint8 { return r.CreateCourierEnvelopesFromPayloadsReply.ErrorCode },
	},
	{
		name: "createCourierEnvelopesFromTombstoneRange",
		run: func(d *Daemon, appID *[AppIDLength]byte, writeCap *bacap.WriteCap) {
			d.createCourierEnvelopesFromTombstoneRange(&Request{AppID: appID, CreateCourierEnvelopesFromTombstoneRange: &thin.CreateCourierEnvelopesFromTombstoneRange{
				QueryID:        new([thin.QueryIDLength]byte),
				DestWriteCap:   writeCap,
				DestStartIndex: writeCap.GetMessageBoxIndex(),
				MaxCount:       1,
				IsStart:        true,
				IsLast:         true,
			}})
		},
		code: func(r *Response) uint8 { return r.CreateCourierEnvelopesFromTombstoneRangeReply.ErrorCode },
	},
}

func requireServiceUnavailable(t *testing.T, h notReadyHandler, prepare func(*Daemon)) {
	t.Run(h.name, func(t *testing.T) {
		d, appID, responseCh := setupDaemonWithMockConn(t)
		prepare(d)
		writeCap, err := bacap.NewWriteCap(rand.Reader)
		require.NoError(t, err)
		h.run(d, appID, writeCap)
		select {
		case resp := <-responseCh:
			require.Equal(t, thin.ThinClientErrorServiceUnavailable, h.code(resp))
		case <-time.After(5 * time.Second):
			t.Fatal("timeout")
		}
	})
}

func TestPigeonholeHandlersNoPKIDocumentServiceUnavailable(t *testing.T) {
	prevAttempts, prevDelay := waitForCurrentDocumentAttempts, waitForCurrentDocumentRetryDelay
	waitForCurrentDocumentAttempts, waitForCurrentDocumentRetryDelay = 1, time.Millisecond
	t.Cleanup(func() {
		waitForCurrentDocumentAttempts, waitForCurrentDocumentRetryDelay = prevAttempts, prevDelay
	})
	clearDocs := func(d *Daemon) { d.client.pki.docs = sync.Map{} }
	copyCommand := notReadyHandler{
		name: "startResendingCopyCommand",
		run: func(d *Daemon, appID *[AppIDLength]byte, writeCap *bacap.WriteCap) {
			d.startResendingCopyCommand(&Request{AppID: appID, StartResendingCopyCommand: &thin.StartResendingCopyCommand{
				QueryID:  new([thin.QueryIDLength]byte),
				WriteCap: writeCap,
			}})
		},
		code: func(r *Response) uint8 { return r.StartResendingCopyCommandReply.ErrorCode },
	}
	for _, h := range append(envelopeBuildingHandlers, copyCommand) {
		requireServiceUnavailable(t, h, clearDocs)
	}
}

func TestPigeonholeHandlersReplicaKeysNotReadyServiceUnavailable(t *testing.T) {
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	docChanges := map[string]func(*cpki.Document){
		"previousEpochKeyOnly": func(doc *cpki.Document) {
			for _, r := range doc.StorageReplicas {
				r.EnvelopeKeys = map[uint64][]byte{replicaEpoch - 1: r.EnvelopeKeys[replicaEpoch]}
			}
		},
		"emptyKey": func(doc *cpki.Document) {
			for _, r := range doc.StorageReplicas {
				r.EnvelopeKeys[replicaEpoch] = []byte{}
			}
		},
		"nilStorageReplicas": func(doc *cpki.Document) {
			doc.StorageReplicas = nil
		},
	}
	for name, change := range docChanges {
		t.Run(name, func(t *testing.T) {
			for _, h := range envelopeBuildingHandlers {
				requireServiceUnavailable(t, h, func(d *Daemon) {
					_, doc := d.client.CurrentDocument()
					change(doc)
				})
			}
		})
	}
}
