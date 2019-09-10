// authority_test.go - Katzenpost voting authority server tests.
// Copyright (C) 2017, 2018  Yawning Angel, masala and David Stainton.
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

package authority_test

import (
	"context"
	"testing"
	"time"

	"github.com/katzenpost/core/crypto/cert"
	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/core/pki"
	ki "github.com/katzenpost/kimchi"
	"github.com/stretchr/testify/assert"
)

const basePort = 42000

// TestBootstrapNonvoting tests that the nonvoting authority bootstraps and provides a consensus document
func TestBootstrapNonvoting(t *testing.T) {
	assert := assert.New(t)
	voting := false
	nVoting := 0
	nProvider := 2
	nMix := 6
	k := ki.NewKimchi(basePort+50, "", nil, voting, nVoting, nProvider, nMix)
	t.Logf("Running Bootstrap Nonvoting mixnet.")
	k.Run()

	go func() {
		defer k.Shutdown()
		_, _, till := epochtime.Now()
		<-time.After(till + epochtime.Period)

		t.Logf("Received shutdown request.")
		p, err := k.PKIClient()
		if assert.NoError(err) {
			epoch, _, _ := epochtime.Now()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()
			c, _, err := p.Get(ctx, epoch)
			assert.NoError(err)
			t.Logf("Got a consensus: %v", c)
		}

		t.Logf("All servers halted.")
	}()

	k.Wait()
	t.Logf("Terminated.")
}

// TestBootstrapVoting tests that the voting authority bootstraps and provides a consensus document
func TestBootstrapVoting(t *testing.T) {
	assert := assert.New(t)
	voting := true
	nVoting := 3
	nProvider := 2
	nMix := 6
	k := ki.NewKimchi(basePort+100, "", nil, voting, nVoting, nProvider, nMix)
	t.Logf("Running Bootstrap Voting mixnet.")
	k.Run()

	go func() {
		defer k.Shutdown()
		_, _, till := epochtime.Now()
		till += epochtime.Period // wait for one vote round, aligned at start of epoch
		<-time.After(till)
		t.Logf("Time is up!")
		// verify that consensus was made
		p, err := k.PKIClient()
		if assert.NoError(err) {
			epoch, _, _ := epochtime.Now()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()
			c, _, err := p.Get(ctx, epoch)
			if assert.NoError(err) {
				t.Logf("Got a consensus: %v", c)
			} else {
				t.Logf("Consensus failed")
			}
		}
	}()

	k.Wait()
	t.Logf("Terminated.")
}

// TestBootstrapThreshold tests that a threshold number of authorities can produce a valid consensus
func TestBootstrapThreshold(t *testing.T) {
	assert := assert.New(t)
	voting := true
	nVoting := 3
	nProvider := 2
	nMix := 6
	k := ki.NewKimchi(basePort, "", nil, voting, nVoting, nProvider, nMix)
	t.Logf("Running Bootstrap Voting mixnet.")
	k.Run()

	// start a goroutine that kills one authority and verifies that
	// consensus is reached with the remaining authorities
	go func() {
		defer k.Shutdown()
		// Varying this delay will set where in the
		// voting protocol the authority fails.
		<-time.After(15 * time.Second)
		t.Logf("Killing an Authority")
		if !assert.True(k.KillAnAuth()) {
			return
		}
		_, _, till := epochtime.Now()
		till += epochtime.Period // wait for one vote round, aligned at start of epoch
		<-time.After(till)
		t.Logf("Time is up!")
		// verify that consensus was made
		p, err := k.PKIClient()
		if assert.NoError(err) {
			epoch, _, _ := epochtime.Now()
			r, err := retry(p, epoch, 3)
			assert.NoError(err)
			s, err := cert.GetSignatures(r)
			if assert.NoError(err) {
				// Confirm exactly 2 signatures are present.
				if assert.Equal(2, len(s)) {
					t.Logf("2 Signatures found on consensus as expected")
				} else {
					t.Logf("Found %d signatures, expected 2", len(s))
				}
			}
		}
	}()

	k.Wait()
	t.Logf("Terminated.")
}

// TestMultipleVotingRounds tests that the authorities produce a fully signed consensus for multiple rounds
func TestMultipleVotingRounds(t *testing.T) {
	assert := assert.New(t)
	voting := true
	nVoting := 3
	nProvider := 2
	nMix := 6
	nRounds := uint64(3)
	k := ki.NewKimchi(basePort+200, "", nil, voting, nVoting, nProvider, nMix)
	t.Logf("Running Voting mixnet for %d rounds.", nRounds)
	k.Run()

	go func() {
		defer k.Shutdown()
		// align with start of epoch
		startEpoch, _, till := epochtime.Now()
		<-time.After(till)
		for i := startEpoch + 1; i < startEpoch+nRounds; i++ {
			_, _, till = epochtime.Now()
			// wait until end of epoch
			<-time.After(till)
			t.Logf("Time is up!")

			// verify that consensus was made for the current epoch
			p, err := k.PKIClient()
			if assert.NoError(err) {
				epoch, _, _ := epochtime.Now()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
				defer cancel()
				c, _, err := p.Get(ctx, epoch)
				if assert.NoError(err) {
					t.Logf("Got a consensus: %v", c)
				} else {
					t.Logf("Consensus failed")
				}
			}
		}
	}()

	k.Wait()
	t.Logf("Terminated.")
}

// TestAuthorityJoinConsensus tests that an authority can join a voting round and produce a fully signed consensus document
func TestAuthorityJoinConsensus(t *testing.T) {
	assert := assert.New(t)
	voting := true
	nVoting := 3
	nProvider := 2
	nMix := 6
	nRounds := uint64(3)
	k := ki.NewKimchi(basePort+300, "", nil, voting, nVoting, nProvider, nMix)
	t.Logf("Running Voting mixnet for %d rounds.", nRounds)
	delay := epochtime.Period // miss the first voting round
	k.RunWithDelayedAuthority(delay)
	go func() {
		defer k.Shutdown()
		// align with start of epoch
		startEpoch, _, till := epochtime.Now()
		<-time.After(till)
		for i := startEpoch + 1; i < startEpoch+nRounds; i++ {
			_, _, till = epochtime.Now()
			// wait until end of epoch
			<-time.After(till)
			t.Logf("Time is up!")

			// verify that consensus was made for each epoch
			p, err := k.PKIClient()
			assert.NoError(err)
			epoch, _, _ := epochtime.Now()
			r, err := retry(p, epoch, 3)
			assert.NoError(err)
			s, err := cert.GetSignatures(r)
			assert.NoError(err)

			// check that we obtained a fully signed consensus in the final round
			if i == startEpoch+nRounds-1 {
				if assert.Equal(nVoting, len(s)) {
					t.Logf("%d Signatures found on consensus as expected", nVoting)
				} else {
					t.Logf("Found %d signatures, expected %d", len(s), nVoting)
				}
			}
		}
	}()

	k.Wait()
	t.Logf("Terminated.")
}

// TestTopologyChange tests that a Mix can fall out of consensus
func TestTopologyChange(t *testing.T) {
	assert := assert.New(t)
	voting := true
	nVoting := 3
	nProvider := 2
	nMix := 6
	nRounds := uint64(5)
	k := ki.NewKimchi(basePort+600, "", nil, voting, nVoting, nProvider, nMix)
	t.Logf("Running Voting mixnet for %d rounds.", nRounds)
	k.Run()

	go func() {
		defer k.Shutdown()
		// align with start of epoch
		startEpoch, _, till := epochtime.Now()
		<-time.After(till)
		for i := startEpoch + 1; i < startEpoch+nRounds; i++ {
			_, _, till = epochtime.Now()
			// wait until end of epoch
			<-time.After(till)
			t.Logf("Time is up!")

			// verify that consensus was made for the current epoch
			p, err := k.PKIClient()
			if assert.NoError(err) {
				epoch, _, _ := epochtime.Now()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
				defer cancel()
				c, _, err := p.Get(ctx, epoch)
				if assert.NoError(err) {
					t.Logf("Got a consensus: %v", c)
				} else {
					t.Logf("Consensus failed")
				}
			}

			// kill 1 mix and verify topology rebalances uniformly
			if i == startEpoch+2 {
				assert.True(k.KillAMix())
			}
		}
	}()

	k.Wait()
	t.Logf("Terminated.")
}

func retry(p pki.Client, epoch uint64, retries int) (reply []byte, err error) {

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	for i := 0; i < retries; i++ {
		_, reply, err = p.Get(ctx, epoch)
		if err == nil {
			return
		}
	}
	return
}
