//go:build docker_test

// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestReticulumBridge is a mixnet client talking to a Reticulum client with
// nothing but Pigeonhole boxes between them. The Reticulum side runs in
// its own container (make -C docker reticulum-start): a mesh replica
// bridged to a Katzenpost replica over its bridge socket, and a bot that
// reads a job's stream through the mesh, which pulls the box from the
// mixnet, and answers on another stream, which the mesh pushes into the
// mixnet. This test writes the question through kpclientd, drops the job,
// and reads the answer through kpclientd.
func TestReticulumBridge(t *testing.T) {
	jobs := os.Getenv("KATZENPOST_RETICULUM_JOBS")
	if jobs == "" {
		t.Skip("set KATZENPOST_RETICULUM_JOBS to the bot's jobs directory (make -C docker reticulum-test)")
	}
	skipInShortMode(t)
	require.NoError(t, os.MkdirAll(jobs, 0o755))

	alice := setupThinClient(t)

	// Alice to the bot, and the bot to Alice. Alice mints both and hands the
	// bot the read side of the first and the write side of the second.
	toBotWrite, toBotRead, toBotIdx := newKeypair(t, alice)
	fromBotWrite, fromBotRead, fromBotIdx := newKeypair(t, alice)

	question := []byte("yo what up? you coming to the party later tonight?")
	writeBox(t, alice, toBotWrite, toBotIdx, question)
	t.Log("question written into the mixnet")

	toBotReadBytes, err := toBotRead.MarshalBinary()
	require.NoError(t, err)
	fromBotWriteBytes, err := fromBotWrite.MarshalBinary()
	require.NoError(t, err)
	job, err := json.Marshal(map[string]string{
		"readcap":  hex.EncodeToString(toBotReadBytes),
		"writecap": hex.EncodeToString(fromBotWriteBytes),
	})
	require.NoError(t, err)
	name := fmt.Sprintf("job-%d", time.Now().UnixNano())
	tmp := filepath.Join(jobs, name+".tmp")
	require.NoError(t, os.WriteFile(tmp, job, 0o644))
	require.NoError(t, os.Rename(tmp, filepath.Join(jobs, name+".json")))
	t.Logf("job %s handed to the Reticulum bot", name)

	// The daemon's read ARQ retries not-found until the box appears; the
	// bot's reply arrives through the bridge push and replication.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	done := make(chan struct{})
	var answer []byte
	var readErr error
	go func() {
		defer close(done)
		ciphertext, envDesc, envHash, _, err := alice.EncryptRead(fromBotRead, fromBotIdx)
		if err != nil {
			readErr = err
			return
		}
		idxBytes, err := fromBotIdx.MarshalBinary()
		if err != nil {
			readErr = err
			return
		}
		res, err := alice.StartResendingEncryptedMessageWithContext(ctx, fromBotRead, nil, idxBytes, nil, envDesc, ciphertext, envHash)
		if err != nil {
			readErr = err
			return
		}
		answer = res.Plaintext
	}()

	// Surface a bot failure early instead of waiting out the read.
	for {
		select {
		case <-done:
			require.NoError(t, readErr)
			require.Equal(t, append([]byte("echo: "), question...), answer)
			t.Logf("answer from the Reticulum client: %q", answer)
			return
		case <-time.After(5 * time.Second):
			if why, err := os.ReadFile(filepath.Join(jobs, name+".failed")); err == nil {
				cancel()
				<-done
				t.Fatalf("Reticulum bot failed the job: %s", why)
			}
		}
	}
}
