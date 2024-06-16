// SPDX-FileCopyrightText: 2024 Katzenpost developers
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// client.go - client
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//go:build docker_test
// +build docker_test

package catshadow

import (
	"context"
	"testing"
	"time"

	_ "net/http/pprof"

	"github.com/katzenpost/hpqc/rand"
	"github.com/stretchr/testify/require"
)

func sendMessage(n int, t *testing.T, sender *Client, recipient string, message []byte) {
	require := require.New(t)
	sender.log.Infof("Test %d Sending message '%s' to %s", n, string(message), recipient)
	sender.SendMessage(recipient, message)
	ctx, cancelFn := context.WithTimeout(context.Background(), time.Minute)
	evt := waitForEvent(ctx, sender.EventSink, &MessageDeliveredEvent{})
	cancelFn()
	_, ok := evt.(*MessageDeliveredEvent)
	require.True(ok)
	sender.log.Infof("Test %d gpt DeliveredEvent for essage '%s' to %s", n, string(message), recipient)
}

func receiveMessage(n int, t *testing.T, receiver *Client, sender string, message []byte) {
	require := require.New(t)
	ctx, cancelFn := context.WithTimeout(context.Background(), time.Minute)
	receiver.log.Infof("Test %d waiting for message '%s' from %s", n, string(message), sender)
	evt := waitForEvent(ctx, receiver.EventSink, &MessageReceivedEvent{})
	cancelFn()
	switch ev := evt.(type) {
	case *MessageReceivedEvent:
		require.Equal(ev.Nickname, sender)
		require.Equal(ev.Message, message)
	default:
        t.Logf("Test %d expected '%s' from %s but got %v", n, string(message), sender, ev)
		t.FailNow()
	}
	receiver.log.Infof("Test %d received message '%s' from %s", n, string(message), sender)
}

func createAliceAndBob(t *testing.T) (*Client, *Client, string, string) {
	require := require.New(t)

	aliceStateFilePath := createRandomStateFile(t)
	bobStateFilePath := createRandomStateFile(t)

	// create 2 statefiles for a pair of contacts
	alice := createCatshadowClientWithState(t, aliceStateFilePath)
	bob := createCatshadowClientWithState(t, bobStateFilePath)

	sharedSecret := []byte("wait for key exchange")
	randBytes := [8]byte{}
	_, err := rand.Reader.Read(randBytes[:])
	require.NoError(err)
	sharedSecret = append(sharedSecret, randBytes[:]...)

	alice.NewContact("bob", sharedSecret)
	bob.NewContact("alice", sharedSecret)

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Minute)
	evt := waitForEvent(ctx, alice.EventSink, &KeyExchangeCompletedEvent{})
	cancelFn()
	ev, ok := evt.(*KeyExchangeCompletedEvent)
	require.True(ok)
	require.NoError(ev.Err)

	ctx, cancelFn = context.WithTimeout(context.Background(), time.Minute)
	evt = waitForEvent(ctx, bob.EventSink, &KeyExchangeCompletedEvent{})
	cancelFn()
	ev, ok = evt.(*KeyExchangeCompletedEvent)
	require.True(ok)
	require.NoError(ev.Err)

	return alice, bob, aliceStateFilePath, bobStateFilePath
}

func TestUpgradeCreate_1(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	alice, bob, aliceStateFilePath, bobStateFilePath := createAliceAndBob(t)

	alice.Shutdown()

	<-time.After(10 * time.Second)

	sendMessage(1, t, bob, "alice", []byte("message 1 from bob"))

	bob.Shutdown()

	// save the statefiles into testdata for using with later versions of catshadow
	err := copyFile(aliceStateFilePath, "testdata/alice1_state")
	require.NoError(err)
	err = copyFile(bobStateFilePath, "testdata/bob1_state")
	require.NoError(err)

}

func TestUpgradeResume_1(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	aliceStateFilePath := createRandomStateFile(t)
	bobStateFilePath := createRandomStateFile(t)

	// copy testdata state into the temporary statefile location
	// because the client will mutate the statefile when started
	err := copyFile("testdata/alice1_state", aliceStateFilePath)
	require.NoError(err)
	err = copyFile("testdata/bob1_state", bobStateFilePath)
	require.NoError(err)

	// start bob
	bob := reloadCatshadowState(t, bobStateFilePath)

	// bob writes to alice
//	sendMessage(1, t, bob, "alice", []byte("message 2 from bob"))

	// start alice
	alice := reloadCatshadowState(t, aliceStateFilePath)

	receiveMessage(1, t, alice, "bob", []byte("message 1 from bob"))
//	receiveMessage(1, t, alice, "bob", []byte("message 2 from bob"))

//	sendMessage(1, t, alice, "bob", []byte("message 1 from alice"))

//	receiveMessage(1, t, bob, "alice", []byte("message 1 from alice"))

	alice.Shutdown()
	bob.Shutdown()
}

func TestUpgradeCreate_2(t *testing.T) {

	require := require.New(t)

	alice, bob, aliceStateFilePath, bobStateFilePath := createAliceAndBob(t)

	sendMessage(2, t, alice, "bob", []byte("message 1 from alice"))
	receiveMessage(2, t, bob, "alice", []byte("message 1 from alice"))

	sendMessage(2, t, bob, "alice", []byte("message 1 from bob"))
	receiveMessage(2, t, alice, "bob", []byte("message 1 from bob"))

	alice.Shutdown()

	sendMessage(2, t, bob, "alice", []byte("message 2 from bob"))

	bob.Shutdown()

	// save the statefiles into testdata for using with later versions of catshadow
	err := copyFile(aliceStateFilePath, "testdata/alice2_state")
	require.NoError(err)
	err = copyFile(bobStateFilePath, "testdata/bob2_state")
	require.NoError(err)

}

func TestUpgradeResume_2(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	aliceStateFilePath := createRandomStateFile(t)
	bobStateFilePath := createRandomStateFile(t)

	// copy testdata state into the temporary statefile location
	// because the client will mutate the statefile when started
	err := copyFile("testdata/alice2_state", aliceStateFilePath)
	require.NoError(err)
	err = copyFile("testdata/bob2_state", bobStateFilePath)
	require.NoError(err)

	// start bob
	bob := reloadCatshadowState(t, bobStateFilePath)

	// start alice
	alice := reloadCatshadowState(t, aliceStateFilePath)

	receiveMessage(2, t, alice, "bob", []byte("message 2 from bob"))

    sendMessage(2, t, alice, "bob", []byte("message 2 from alice"))
    receiveMessage(2, t, bob, "alice", []byte("message 2 from alice"))
     
    sendMessage(2, t, bob, "alice", []byte("message 3 from bob"))
    receiveMessage(2, t, alice, "bob", []byte("message 3 from bob"))

    alice.Shutdown()
    bob.Shutdown()
}
