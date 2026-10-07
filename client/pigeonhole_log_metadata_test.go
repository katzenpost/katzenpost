// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package client

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/pigeonhole"
)

func pigeonholeLogToFile(t *testing.T, d *Daemon) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "daemon.log")
	backend, err := log.New(path, "debug", false)
	require.NoError(t, err)
	d.log = backend.GetLogger("pigeonhole-log-metadata")
	return path
}

func pigeonholeLogText(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(b)
}

func pigeonholeLogBoxIDHex(t *testing.T, writeCap *bacap.WriteCap, idx *bacap.MessageBoxIndex) string {
	t.Helper()
	pos, err := writeCap.ReadCap().PositionAt(idx)
	require.NoError(t, err)
	boxID, err := pigeonhole.BoxID(pos)
	require.NoError(t, err)
	return hex.EncodeToString(boxID[:8])
}

func awaitPigeonholeResponse(t *testing.T, ch chan *Response) *Response {
	t.Helper()
	select {
	case resp := <-ch:
		return resp
	case <-time.After(5 * time.Second):
		t.Fatal("no response")
		return nil
	}
}

func TestEncryptReadWriteDoNotLogBoxID(t *testing.T) {
	d, appID, responseCh := setupDaemonWithMockConn(t)
	path := pigeonholeLogToFile(t, d)

	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	idx := writeCap.GetMessageBoxIndex()
	boxIDHex := pigeonholeLogBoxIDHex(t, writeCap, idx)

	d.encryptRead(&Request{AppID: appID, EncryptRead: &thin.EncryptRead{
		QueryID: &[thin.QueryIDLength]byte{1}, ReadCap: writeCap.ReadCap(), MessageBoxIndex: idx,
	}})
	require.Equal(t, thin.ThinClientSuccess, awaitPigeonholeResponse(t, responseCh).EncryptReadReply.ErrorCode)

	d.encryptWrite(&Request{AppID: appID, EncryptWrite: &thin.EncryptWrite{
		QueryID: &[thin.QueryIDLength]byte{2}, Plaintext: []byte("hello"), WriteCap: writeCap, MessageBoxIndex: idx,
	}})
	require.Equal(t, thin.ThinClientSuccess, awaitPigeonholeResponse(t, responseCh).EncryptWriteReply.ErrorCode)

	text := pigeonholeLogText(t, path)
	require.Contains(t, text, "encryptWrite")
	require.NotContains(t, text, boxIDHex, "BoxID written to the log")
}

func TestCreateCourierEnvelopesFromPayloadDoesNotLogBoxID(t *testing.T) {
	d, appID, responseCh := setupDaemonWithMockConn(t)
	path := pigeonholeLogToFile(t, d)

	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	idx := writeCap.GetMessageBoxIndex()
	boxIDHex := pigeonholeLogBoxIDHex(t, writeCap, idx)

	d.createCourierEnvelopesFromPayload(&Request{AppID: appID, CreateCourierEnvelopesFromPayload: &thin.CreateCourierEnvelopesFromPayload{
		QueryID: &[thin.QueryIDLength]byte{3}, Payload: []byte("hello"), DestWriteCap: writeCap, DestStartIndex: idx, IsStart: true, IsLast: true,
	}})
	require.Equal(t, thin.ThinClientSuccess, awaitPigeonholeResponse(t, responseCh).CreateCourierEnvelopesFromPayloadReply.ErrorCode)

	text := pigeonholeLogText(t, path)
	require.Contains(t, text, "createCourierEnvelopesFromPayload")
	require.NotContains(t, text, boxIDHex, "BoxID written to the log")
}

func TestStartResendingLogLineDoesNotLogBoxIDOrEnvelopeHash(t *testing.T) {
	d, _, _ := setupDaemonWithMockConn(t)
	path := pigeonholeLogToFile(t, d)

	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	idx := writeCap.GetMessageBoxIndex()
	derived, err := writeCap.ReadCap().DeriveBoxID(idx)
	require.NoError(t, err)
	idxBytes, err := idx.MarshalBinary()
	require.NoError(t, err)
	envHash := &[32]byte{}
	copy(envHash[:], []byte("envelope-hash-for-the-log-test!!"))

	d.logBoxIDForRequest(&thin.StartResendingEncryptedMessage{
		ReadCap: writeCap.ReadCap(), MessageBoxIndex: idxBytes, EnvelopeHash: envHash,
	}, true)

	text := pigeonholeLogText(t, path)
	require.Contains(t, text, "startResendingEncryptedMessage")
	require.NotContains(t, text, hex.EncodeToString(derived.Bytes()[:8]), "box identifier written to the log")
	require.NotContains(t, text, hex.EncodeToString(envHash[:8]), "EnvelopeHash written to the log")
}

func TestCancelResendingDoesNotLogEnvelopeOrWriteCapHash(t *testing.T) {
	d, appID, responseCh := setupDaemonWithMockConn(t)
	path := pigeonholeLogToFile(t, d)

	envHash := &[32]byte{}
	copy(envHash[:], []byte("envelope-hash-never-registered!!"))
	writeCapHash := &[32]byte{}
	copy(writeCapHash[:], []byte("write-cap-hash-never-registered!"))

	d.cancelResendingEncryptedMessage(&Request{AppID: appID, CancelResendingEncryptedMessage: &thin.CancelResendingEncryptedMessage{
		QueryID: &[thin.QueryIDLength]byte{4}, EnvelopeHash: envHash,
	}})
	awaitPigeonholeResponse(t, responseCh)
	d.cancelResendingCopyCommand(&Request{AppID: appID, CancelResendingCopyCommand: &thin.CancelResendingCopyCommand{
		QueryID: &[thin.QueryIDLength]byte{5}, WriteCapHash: writeCapHash,
	}})
	awaitPigeonholeResponse(t, responseCh)

	text := pigeonholeLogText(t, path)
	require.Contains(t, text, "not found")
	require.NotContains(t, text, hex.EncodeToString(envHash[:8]), "EnvelopeHash written to the log")
	require.NotContains(t, text, hex.EncodeToString(writeCapHash[:8]), "WriteCapHash written to the log")
}
