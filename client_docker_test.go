// SPDX-FileCopyrightText: 2019, David Stainton <dawuud@riseup.net>
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

// +build docker_test

package catshadow

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/katzenpost/catshadow/config"
	"github.com/katzenpost/client"
	cConfig "github.com/katzenpost/client/config"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/stretchr/testify/require"
)

func getClientState(c *Client) *State {
	contacts := []*Contact{}
	for _, contact := range c.contacts {
		contacts = append(contacts, contact)
	}
	return &State{
		SpoolReadDescriptor: c.spoolReadDescriptor,
		Contacts:            contacts,
		LinkKey:             c.linkKey,
		User:                c.user,
		Provider:            c.client.Provider(),
		Conversations:       c.GetAllConversations(),
	}
}

func createRandomStateFile(t *testing.T) string {
	require := require.New(t)

	tmpDir, err := ioutil.TempDir("", "catshadow_test")
	require.NoError(err)
	id := [6]byte{}
	_, err = rand.Reader.Read(id[:])
	require.NoError(err)
	stateFile := filepath.Join(tmpDir, fmt.Sprintf("%x.catshadow.state", id))
	_, err = os.Stat(stateFile)
	require.True(os.IsNotExist(err))
	return stateFile
}

func createCatshadowClientWithState(t *testing.T, stateFile string) *Client {
	require := require.New(t)

	// Load catshadow config file.
	catshadowCfg, err := config.LoadFile("testdata/catshadow.toml")
	require.NoError(err)
	var stateWorker *StateWriter
	var catShadowClient *Client
	cfg, err := catshadowCfg.ClientConfig()
	require.NoError(err)

	cfg, linkKey := client.AutoRegisterRandomClient(cfg)
	//cfg.Logging.Level = "INFO" // client verbosity reductionism
	c, err := client.New(cfg)
	require.NoError(err)
	passphrase := []byte("")
	stateWorker, err = NewStateWriter(c.GetLogger("catshadow_state"), stateFile, passphrase)
	require.NoError(err)
	backendLog, err := catshadowCfg.InitLogBackend()
	require.NoError(err)

	user := fmt.Sprintf("%x", linkKey.PublicKey().Bytes())
	catShadowClient, err = NewClientAndRemoteSpool(backendLog, c, stateWorker, user, linkKey)
	require.NoError(err)

	// Start catshadow client.
	stateWorker.Start()
	catShadowClient.Start()

	return catShadowClient
}

func reloadCatshadowState(t *testing.T, stateFile string) *Client {
	require := require.New(t)

	// Load catshadow config file.
	catshadowCfg, err := config.LoadFile("testdata/catshadow.toml")
	require.NoError(err)
	var stateWorker *StateWriter
	var catShadowClient *Client

	cfg, err := catshadowCfg.ClientConfig()
	require.NoError(err)

	passphrase := []byte("")
	key := stretchKey(passphrase)
	state, err := decryptStateFile(stateFile, key)
	require.NoError(err)
	cfg.Account = &cConfig.Account{
		User:     state.User,
		Provider: state.Provider,
	}

	logBackend, err := catshadowCfg.InitLogBackend()
	require.NoError(err)
	c, err := client.New(cfg)
	require.NoError(err)
	stateWorker, state, err = LoadStateWriter(c.GetLogger(cfg.Account.User+" "+"catshadow_state"), stateFile, passphrase)
	require.NoError(err)

	catShadowClient, err = New(logBackend, c, stateWorker, state)
	require.NoError(err)

	// Start catshadow client.
	stateWorker.Start()
	catShadowClient.Start()

	return catShadowClient
}

func TestDockerPandaSuccess(t *testing.T) {
	require := require.New(t)

	aliceState := createRandomStateFile(t)
	alice := createCatshadowClientWithState(t, aliceState)
	bobState := createRandomStateFile(t)
	bob := createCatshadowClientWithState(t, bobState)

	sharedSecret := []byte("There is a certain kind of small town that grows like a boil on the ass of every Army base in the world.")
	randBytes := [8]byte{}
	_, err := rand.Reader.Read(randBytes[:])
	require.NoError(err)
	sharedSecret = append(sharedSecret, randBytes[:]...)

	alice.NewContact("bob", sharedSecret)
	bob.NewContact("alice", sharedSecret)

loop1:
	for {
		ev := <-alice.EventSink
		switch event := ev.(type) {
		case *KeyExchangeCompletedEvent:
			require.Nil(event.Err)
			break loop1
		default:
		}
	}

loop2:
	for {
		ev := <-bob.EventSink
		switch event := ev.(type) {
		case *KeyExchangeCompletedEvent:
			require.Nil(event.Err)
			break loop2
		default:
		}
	}

	alice.Shutdown()
	bob.Shutdown()
}

func TestDockerPandaTagContendedError(t *testing.T) {
	require := require.New(t)

	aliceStateFilePath := createRandomStateFile(t)
	alice := createCatshadowClientWithState(t, aliceStateFilePath)
	bobStateFilePath := createRandomStateFile(t)
	bob := createCatshadowClientWithState(t, bobStateFilePath)

	sharedSecret := []byte("twas brillig and the slithy toves")
	randBytes := [8]byte{}
	_, err := rand.Reader.Read(randBytes[:])
	require.NoError(err)
	sharedSecret = append(sharedSecret, randBytes[:]...)

	alice.NewContact("bob", sharedSecret)
	bob.NewContact("alice", sharedSecret)

loop1:
	for {
		ev := <-alice.EventSink
		switch event := ev.(type) {
		case *KeyExchangeCompletedEvent:
			require.Nil(event.Err)
			break loop1
		default:
		}
	}

loop2:
	for {
		ev := <-bob.EventSink
		switch event := ev.(type) {
		case *KeyExchangeCompletedEvent:
			require.Nil(event.Err)
			break loop2
		default:
		}
	}

	alice.Shutdown()
	bob.Shutdown()

	// second phase of test, use same panda shared secret
	// in order to test that it invokes a tag contended error
	adaState := createRandomStateFile(t)
	ada := createCatshadowClientWithState(t, adaState)
	jeffState := createRandomStateFile(t)
	jeff := createCatshadowClientWithState(t, jeffState)

	ada.NewContact("jeff", sharedSecret)
	jeff.NewContact("ada", sharedSecret)

loop3:
	for {
		ev := <-ada.EventSink
		switch event := ev.(type) {
		case *KeyExchangeCompletedEvent:
			require.NotNil(event.Err)
			break loop3
		default:
		}
	}

loop4:
	for {
		ev := <-jeff.EventSink
		switch event := ev.(type) {
		case *KeyExchangeCompletedEvent:
			require.NotNil(event.Err)
			break loop4
		default:
		}
	}

	ada.Shutdown()
	jeff.Shutdown()
}

func TestDockerSendReceive(t *testing.T) {
	require := require.New(t)

	aliceStateFilePath := createRandomStateFile(t)
	alice := createCatshadowClientWithState(t, aliceStateFilePath)
	bobStateFilePath := createRandomStateFile(t)
	bob := createCatshadowClientWithState(t, bobStateFilePath)
	malStateFilePath := createRandomStateFile(t)
	mal := createCatshadowClientWithState(t, malStateFilePath)

	sharedSecret := []byte(`oxcart pillage village bicycle gravity socks`)
	sharedSecret2 := make([]byte, len(sharedSecret))
	randBytes := [8]byte{}
	_, err := rand.Reader.Read(randBytes[:])
	require.NoError(err)
	_, err = rand.Reader.Read(sharedSecret2[:])
	require.NoError(err)
	sharedSecret = append(sharedSecret, randBytes[:]...)

	alice.NewContact("bob", sharedSecret)
	// bob has 2 contacts
	bob.NewContact("alice", sharedSecret)
	bob.NewContact("mal", sharedSecret2)
	mal.NewContact("bob", sharedSecret2)

	bobKXFinishedChan := make(chan bool)
	bobReceivedMessageChan := make(chan bool)
	bobSentChan := make(chan bool)
	bobDeliveredChan := make(chan bool)
	go func() {
		for {
			ev := <-bob.EventSink
			switch event := ev.(type) {
			case *KeyExchangeCompletedEvent:
				require.Nil(event.Err)
				bobKXFinishedChan <- true
			case *MessageReceivedEvent:
				// fields: Nickname, Message, Timestamp
				bob.log.Debugf("BOB RECEIVED MESSAGE from %s:\n%s", event.Nickname, string(event.Message))
				bobReceivedMessageChan <- true
			case *MessageDeliveredEvent:
				require.Equal(event.Nickname, "mal")
				bobDeliveredChan <- true
			case *MessageSentEvent:
				bob.log.Debugf("BOB SENT MESSAGE to %s", event.Nickname)
				require.Equal(event.Nickname, "mal")
				bobSentChan <- true
			default:
			}
		}
	}()

	aliceKXFinishedChan := make(chan bool)
	aliceSentChan := make(chan bool)
	aliceDeliveredChan := make(chan bool)
	go func() {
		for {
			ev := <-alice.EventSink
			switch event := ev.(type) {
			case *KeyExchangeCompletedEvent:
				require.Nil(event.Err)
				aliceKXFinishedChan <- true
				break
			case *MessageSentEvent:
				alice.log.Debugf("ALICE SENT MESSAGE to %s", event.Nickname)
				require.Equal(event.Nickname, "bob")
				aliceSentChan <- true
			case *MessageDeliveredEvent:
				require.Equal(event.Nickname, "bob")
				aliceDeliveredChan <- true
			default:
			}
		}
	}()

	malKXFinishedChan := make(chan bool)
	malSentChan := make(chan bool)
	malReceivedMessageChan := make(chan bool)
	malDeliveredChan := make(chan bool)
	go func() {
		for {
			ev := <-mal.EventSink
			switch event := ev.(type) {
			case *KeyExchangeCompletedEvent:
				require.Nil(event.Err)
				malKXFinishedChan <- true
			case *MessageReceivedEvent:
				// fields: Nickname, Message, Timestamp
				require.Equal(event.Nickname, "bob")
				mal.log.Debugf("MAL RECEIVED MESSAGE:\n%s", string(event.Message))
				malReceivedMessageChan <- true
			case *MessageDeliveredEvent:
				require.Equal(event.Nickname, "bob")
				malDeliveredChan <- true
			case *MessageSentEvent:
				mal.log.Debugf("MAL SENT MESSAGE to %s", event.Nickname)
				require.Equal(event.Nickname, "bob")
				malSentChan <- true

			default:
			}
		}
	}()

	<-bobKXFinishedChan
	<-aliceKXFinishedChan
	<-malKXFinishedChan
	<-bobKXFinishedChan
	alice.SendMessage("bob", []byte(`Data encryption is used widely to protect the content of Internet
communications and enables the myriad of activities that are popular today,
from online banking to chatting with loved ones. However, encryption is not
sufficient to protect the meta-data associated with the communications.
`))
	<-aliceSentChan
	<-aliceDeliveredChan
	<-bobReceivedMessageChan

	alice.SendMessage("bob", []byte(`Since 1979, there has been active academic research into communication
meta-data protection, also called anonymous communication networking, that has
produced various designs. Of these, mix networks are among the most practical
and can readily scale to millions of users.
`))
	<-aliceSentChan
	<-aliceDeliveredChan
	<-bobReceivedMessageChan

	mal.SendMessage("bob", []byte(`Hello bob`))
	<-malSentChan
	<-malDeliveredChan
	<-bobReceivedMessageChan

	// bob replies to mal
	bob.SendMessage("mal", []byte(`Hello mal`))
	<-bobSentChan
	<-bobDeliveredChan
	<-malReceivedMessageChan

	// Test statefile persistence of conversation.

	alice.log.Debug("LOADING ALICE'S CONVERSATION")
	aliceConvesation := alice.GetConversation("bob")
	for i, mesg := range aliceConvesation {
		alice.log.Debugf("%d outbound %v message:\n%s\n", i, mesg.Outbound, mesg.Plaintext)
	}

	bob.log.Debug("LOADING BOB'S CONVERSATION")
	bobConvesation := bob.GetConversation("alice")
	for i, mesg := range bobConvesation {
		bob.log.Debugf("%d outbound %v message:\n%s\n", i, mesg.Outbound, mesg.Plaintext)
	}

	mal.log.Debug("LOADING MAL'S CONVERSATION")
	malConvesation := mal.GetConversation("bob")
	for i, mesg := range malConvesation {
		bob.log.Debugf("%d outbound %v message:\n%s\n", i, mesg.Outbound, mesg.Plaintext)
	}

	alice.Shutdown()
	bob.Shutdown()
	mal.Shutdown()

	newAlice := reloadCatshadowState(t, aliceStateFilePath)
	newAlice.log.Debug("LOADING ALICE'S CONVERSATION WITH BOB")
	aliceConvesation = newAlice.GetConversation("bob")
	for i, mesg := range aliceConvesation {
		newAlice.log.Debugf("%d outbound %v message:\n%s\n", i, mesg.Outbound, mesg.Plaintext)
	}

	newBob := reloadCatshadowState(t, bobStateFilePath)
	newBob.log.Debug("LOADING BOB'S CONVERSATION WITH ALICE")
	bobConvesation = newBob.GetConversation("alice")
	for i, mesg := range bobConvesation {
		newBob.log.Debugf("%d outbound %v message:\n%s\n", i, mesg.Outbound, mesg.Plaintext)
	}

	newMal := reloadCatshadowState(t, malStateFilePath)
	newMal.log.Debug("LOADING MAL'S CONVERSATION WITH BOB")
	malBobConversation := newMal.GetConversation("bob")
	for i, mesg := range malBobConversation {
		newMal.log.Debugf("%d outbound %v message:\n%s\n", i, mesg.Outbound, mesg.Plaintext)
		if !mesg.Outbound {
			require.True(bytes.Equal(mesg.Plaintext, []byte(`Hello mal`)))
		} else {
			require.True(bytes.Equal(mesg.Plaintext, []byte(`Hello bob`)))
		}
	}

	newBob.log.Debug("LOADING BOB'S CONVERSATION WITH MAL")
	bobMalConversation := newBob.GetConversation("mal")
	for i, mesg := range bobMalConversation {
		newBob.log.Debugf("%d outbound %v message:\n%s\n", i, mesg.Outbound, mesg.Plaintext)
		if !mesg.Outbound {
			require.True(bytes.Equal(mesg.Plaintext, []byte(`Hello bob`)))
		} else {
			require.True(bytes.Equal(mesg.Plaintext, []byte(`Hello mal`)))
		}
	}

	newAliceState := getClientState(newAlice)
	aliceState := getClientState(alice)
	aliceBobConvo1 := aliceState.Conversations["bob"]
	aliceBobConvo2 := newAliceState.Conversations["bob"]
	newAlice.log.Debug("convo1\n")
	for i, message := range aliceBobConvo1 {
		require.True(bytes.Equal(message.Plaintext, aliceBobConvo2[i].Plaintext))
		// XXX require.True(message.Timestamp.Equal(aliceBobConvo2[i].Timestamp))
	}
	newAlice.Shutdown()
	newBob.Shutdown()
}
