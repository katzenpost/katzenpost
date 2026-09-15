//go:build docker_test

// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"bytes"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"testing"

	"github.com/katzenpost/hpqc/hash"
)

func TestLegacyTests(t *testing.T) {
	t.Parallel()
	// Setup signal handling for graceful shutdown
	haltCh := make(chan os.Signal, 1)
	signal.Notify(haltCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-haltCh
		close(shutdownCh)
		t.Log("Interrupt caught. Shutdown")
	}()

	t.Run("TestDockerMultiplexClients", func(t *testing.T) {
		t.Parallel()
		retrySubtest(t, 3, testDockerMultiplexClients)
	})
	t.Run("TestDockerClientSendReceive", func(t *testing.T) {
		t.Parallel()
		retrySubtest(t, 3, testDockerClientSendReceive)
	})
}

func retrySubtest(t *testing.T, maxAttempts int, fn func(t *testing.T) error) {
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := fn(t)
		if err == nil {
			return
		}
		if attempt < maxAttempts {
			t.Logf("attempt %d/%d failed: %s, retrying...", attempt, maxAttempts, err)
		} else {
			t.Fatalf("all %d attempts failed, last error: %s", maxAttempts, err)
		}
	}
}

func testDockerMultiplexClients(t *testing.T) error {
	client1, pingTargets := setupClientAndTargets(t)
	defer client1.Close()

	client2 := setupThinClient(t)
	defer client2.Close()

	message1 := []byte("hello alice, this is bob.")
	nodeIdKey := hash.Sum256(pingTargets[0].IdentityKey)

	reply, err := sendAndWait(t, client1, message1, &nodeIdKey, []byte("+echo"))
	if err != nil {
		return fmt.Errorf("client1 echo: %w", err)
	}
	if !bytes.Equal(message1, reply[:len(message1)]) {
		return fmt.Errorf("client1 reply mismatch")
	}

	reply, err = sendAndWait(t, client2, message1, &nodeIdKey, []byte("+echo"))
	if err != nil {
		return fmt.Errorf("client2 echo: %w", err)
	}
	if !bytes.Equal(message1, reply[:len(message1)]) {
		return fmt.Errorf("client2 reply mismatch")
	}
	return nil
}

func testDockerClientSendReceive(t *testing.T) error {
	client, pingTargets := setupClientAndTargets(t)
	defer client.Close()

	message1 := []byte("hello alice, this is bob.")
	nodeIdKey := hash.Sum256(pingTargets[0].IdentityKey)

	t.Log("BEFORE sendAndWait")
	reply, err := sendAndWait(t, client, message1, &nodeIdKey, []byte("+testdest"))
	t.Log("AFTER sendAndWait")
	if err != nil {
		return fmt.Errorf("sendAndWait: %w", err)
	}
	if !bytes.Equal(message1, reply[:len(message1)]) {
		return fmt.Errorf("reply mismatch")
	}

	err = repeatSendAndWait(t, client, message1, &nodeIdKey, []byte("+testdest"), 5)
	if err != nil {
		return fmt.Errorf("repeatSendAndWait: %w", err)
	}
	return nil
}

func init() {
	go func() {
		http.ListenAndServe("localhost:4242", nil)
	}()
	runtime.SetMutexProfileFraction(1)
	runtime.SetBlockProfileRate(1)
}
