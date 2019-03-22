// state_test.go - Voting authority state machine tests.
// Copyright (C) 2018  David Stainton
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

package server

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/katzenpost/authority/internal/s11n"
	"github.com/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/pki"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
)

func TestSharedRandomVerify(t *testing.T) {
	assert := assert.New(t)
	srv := new(SharedRandom)
	commit, err := srv.Commit(1234)
	assert.NoError(err, "wtf")
	assert.True(len(commit) == s11n.SharedRandomLength)
	srv.SetCommit(commit)
	assert.True(bytes.Equal(commit, srv.GetCommit()))
	t.Logf("commit %v", commit)
	assert.True(bytes.Equal(commit, srv.GetCommit()))
	reveal := srv.Reveal()
	t.Logf("h(reveal) %v", sha3.Sum256(reveal))
	t.Logf("reveal %v", reveal)
	t.Logf("len(reveal): %v", len(reveal))
	assert.True(len(reveal) == s11n.SharedRandomLength)
	assert.True(srv.Verify(reveal))
}

func TestSharedRandomCommit(t *testing.T) {
	assert := assert.New(t)
	srv := new(SharedRandom)
	commit, err := srv.Commit(1234)
	assert.NoError(err, "wtf")
	assert.True(len(commit) == s11n.SharedRandomLength)
}

func TestSharedRandomSetCommit(t *testing.T) {
	assert := assert.New(t)
	srv := new(SharedRandom)
	commit, err := srv.Commit(1234)
	assert.NoError(err, "wtf")
	srv.SetCommit(commit)
	assert.True(bytes.Equal(commit, srv.GetCommit()))
}

func TestVoteThreshold(t *testing.T) {
	assert := assert.New(t)
	testDir, err := ioutil.TempDir("", "authority")
	assert.NoError(err, "wtf")

	cfg := &config.Config{
		Logging: &config.Logging{
			Disable: false,
			File:    "",
			Level:   "Debug",
		},
		Authority: &config.Authority{
			DataDir: testDir,
		},
	}

	mixIdentityPrivateKey, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err, "wtf")
	server := &Server{
		cfg:         cfg,
		identityKey: mixIdentityPrivateKey,
	}
	server.initLogging()
	_, err = newState(server)
	assert.NoError(err, "wtf")

	targetMix := &pki.MixDescriptor{
		Name:        "NSA_Spy_Sattelite_Mix001",
		IdentityKey: server.IdentityKey(),
		LinkKey:     nil,
		MixKeys:     nil,
		Addresses:   nil,
		Kaetzchen:   nil,
		Layer:       1,
		LoadWeight:  0,
	}
	docWithTarget := &pki.Document{
		Epoch:           1,
		Mu:              3.141,
		MuMaxDelay:      3,
		LambdaP:         2.6,
		LambdaPMaxDelay: 42,
		Topology: [][]*pki.MixDescriptor{
			{targetMix},
		},
		Providers: []*pki.MixDescriptor{},
	}
	docWithoutTarget := &pki.Document{
		Epoch:           1,
		Mu:              3.141,
		MuMaxDelay:      3,
		LambdaP:         2.6,
		LambdaPMaxDelay: 42,
		Topology:        [][]*pki.MixDescriptor{[]*pki.MixDescriptor{}},
		Providers:       []*pki.MixDescriptor{},
	}

	voteThresholdTests := []struct {
		votes  []*pki.Document
		thresh int
		want   *pki.MixDescriptor
	}{
		{
			votes: []*pki.Document{
				docWithTarget,
				docWithTarget,
				docWithTarget,
			},
			thresh: 2,
			want:   targetMix,
		},
		{
			votes: []*pki.Document{
				docWithoutTarget,
				docWithTarget,
				docWithTarget,
			},
			thresh: 2,
			want:   targetMix,
		},
		{
			votes: []*pki.Document{
				docWithoutTarget,
				docWithoutTarget,
				docWithoutTarget,
			},
			thresh: 2,
			want:   nil,
		},
		{
			votes: []*pki.Document{
				docWithTarget,
				docWithTarget,
				docWithTarget,
				docWithTarget,
				docWithTarget,
				docWithTarget,
				docWithoutTarget,
				docWithoutTarget,
				docWithoutTarget,
				docWithoutTarget,
			},
			thresh: 5,
			want:   targetMix,
		},
	}

	// Depends on deprecated method that isn't used elsewhere
	for i := range voteThresholdTests {
		t.Logf("test case %d skipped, fixme", i)
	}
	//	agreed := state.agreedDescriptor(mixIdentityPrivateKey.PublicKey().ByteArray(), voteThresholdTests[i].votes)
	//	if voteThresholdTests[i].want == nil {
	//		assert.Nil(agreed)
	//	}
	//}
}
