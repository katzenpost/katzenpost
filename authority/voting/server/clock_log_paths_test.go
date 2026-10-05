// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

const clockLogPattern = `\(local epoch=\d+ elapsed=\S+ phase=\S+\)`

func clockLogFile(t *testing.T, st *state) string {
	p := filepath.Join(t.TempDir(), "clock.log")
	lb, err := log.New(p, "NOTICE", false)
	require.NoError(t, err)
	st.log = lb.GetLogger("clock")
	return p
}

func TestReceiveRejectionsCarryLocalClock(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	voting := epoch + 2
	states, _ := buildScenarioStates(t, 2, voting, nil)
	from, to := states[0], states[1]
	p := clockLogFile(t, to)
	to.votingEpoch = voting
	pk := hash.Sum256From(from.s.identityPublicKey)
	id := from.s.identityPublicKey

	reveal := func(e uint64) *commands.Reveal {
		body := make([]byte, 40)
		binary.BigEndian.PutUint64(body, e)
		signed, err := cert.Sign(from.s.identityPrivateKey, id, body, voting+5)
		require.NoError(t, err)
		return &commands.Reveal{Epoch: e, PublicKey: id, Payload: signed}
	}

	cases := []struct {
		name string
		run  func() uint8
		want uint8
		line string
	}{
		{"cert late", func() uint8 {
			return to.onCertUpload(&commands.Cert{Epoch: voting - 1, PublicKey: id}, pk[:]).(*commands.CertStatus).ErrorCode
		}, commands.CertTooLate, `Certificate from .* received too late: `},
		{"cert early", func() uint8 {
			return to.onCertUpload(&commands.Cert{Epoch: voting + 1, PublicKey: id}, pk[:]).(*commands.CertStatus).ErrorCode
		}, commands.CertTooEarly, `Certificate from .* received too early: `},
		{"reveal late", func() uint8 {
			return to.onRevealUpload(reveal(voting-1), pk[:]).(*commands.RevealStatus).ErrorCode
		}, commands.RevealTooLate, `Reveal from .* received too late: `},
		{"reveal early", func() uint8 {
			return to.onRevealUpload(reveal(voting+1), pk[:]).(*commands.RevealStatus).ErrorCode
		}, commands.RevealTooEarly, `Reveal from .* received too early: `},
		{"vote late", func() uint8 {
			return to.onVoteUpload(&commands.Vote{Epoch: voting - 1, PublicKey: id}, pk[:]).(*commands.VoteStatus).ErrorCode
		}, commands.VoteTooLate, `Vote from .* received too late: `},
		{"vote early", func() uint8 {
			return to.onVoteUpload(&commands.Vote{Epoch: voting + 1, PublicKey: id}, pk[:]).(*commands.VoteStatus).ErrorCode
		}, commands.VoteTooEarly, `Vote from .* received too early: `},
		{"sig late", func() uint8 {
			return to.onSigUpload(&commands.Sig{Epoch: voting - 1, PublicKey: id}, pk[:]).(*commands.SigStatus).ErrorCode
		}, commands.SigTooLate, `Signature from .* received too late: `},
		{"sig early", func() uint8 {
			return to.onSigUpload(&commands.Sig{Epoch: voting + 1, PublicKey: id}, pk[:]).(*commands.SigStatus).ErrorCode
		}, commands.SigTooEarly, `Signature from .* received too early: `},
	}
	for _, c := range cases {
		require.Equal(t, c.want, c.run(), c.name)
	}
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	for _, c := range cases {
		require.Regexp(t, c.line+`.* `+clockLogPattern, string(b), c.name)
	}
}

func clockLogStatus(cmd commands.Command, code uint8) commands.Command {
	switch cmd.(type) {
	case *commands.Cert:
		return &commands.CertStatus{ErrorCode: code}
	case *commands.Vote:
		return &commands.VoteStatus{ErrorCode: code}
	case *commands.Reveal:
		return &commands.RevealStatus{ErrorCode: code}
	case *commands.Sig:
		return &commands.SigStatus{ErrorCode: code}
	}
	return nil
}

func clockLogSender(t *testing.T, code uint8) (*state, string) {
	sender, _, _ := mkAuthState(t, "sender", "Xwing")
	sender.hasIPv4 = true
	sender.s.cfg.Server.PersistentPeerConns = false
	sender.s.cfg.Server.PeerRetryBaseDelay = 5 * time.Millisecond
	sender.s.cfg.Server.PeerRetryMaxDelay = 20 * time.Millisecond
	p := clockLogFile(t, sender)
	_, respID, respLink := mkAuthState(t, "responder", "Xwing")
	rh := hash.Sum256From(respID)
	sender.authorizedAuthorities[rh] = true
	sender.s.cfg.Authorities = []*config.Authority{{
		Identifier:        "responder",
		IdentityPublicKey: respID,
		Addresses:         []string{"tcp://127.0.0.1:1"},
	}}
	respCfg := &wire.SessionConfig{
		KEMScheme:          kemschemes.ByName("Xwing"),
		PKISignatureScheme: signschemes.ByName("Ed25519"),
		Authenticator:      acceptAuthenticator{},
		AdditionalData:     rh[:],
		AuthenticationKey:  respLink,
		RandomReader:       rand.Reader,
	}
	sender.dialContextFn = func(ctx context.Context, network, addr string) (net.Conn, error) {
		cli, srv := net.Pipe()
		go func() {
			defer srv.Close()
			rs, err := wire.NewPKISession(respCfg, false)
			if err != nil {
				return
			}
			defer rs.Close()
			if err := rs.Initialize(context.Background(), srv); err != nil {
				return
			}
			for {
				cmd, err := rs.RecvCommand(context.Background())
				if err != nil {
					return
				}
				resp := clockLogStatus(cmd, code)
				if resp == nil || rs.SendCommand(context.Background(), resp) != nil {
					return
				}
			}
		}()
		return cli, nil
	}
	return sender, p
}

func clockLogShortDeadline(t *testing.T, d *time.Duration) {
	old := *d
	_, elapsed, _ := epochtime.Now()
	*d = elapsed + 5*time.Second + 600*time.Millisecond
	t.Cleanup(func() { *d = old })
}

func TestSendRejectionsCarryLocalClock(t *testing.T) {
	cases := []struct {
		name     string
		code     uint8
		deadline *time.Duration
		send     func(s *state)
		line     string
	}{
		{"cert late", commands.CertTooLate, &AuthorityCertDeadline, func(s *state) { s.sendCertToAuthorities([]byte("c"), 1) }, `Cert rejected \(too late\) by responder `},
		{"cert early", commands.CertTooEarly, &AuthorityCertDeadline, func(s *state) { s.sendCertToAuthorities([]byte("c"), 1) }, `Cert rejected \(too early\) by responder `},
		{"vote late", commands.VoteTooLate, &AuthorityVoteDeadline, func(s *state) { s.sendVoteToAuthorities([]byte("v"), 1) }, `Vote rejected \(too late\) by responder `},
		{"vote early", commands.VoteTooEarly, &AuthorityVoteDeadline, func(s *state) { s.sendVoteToAuthorities([]byte("v"), 1) }, `Vote rejected \(too early\) by responder `},
		{"reveal late", commands.RevealTooLate, &AuthorityRevealDeadline, func(s *state) { s.sendRevealToAuthorities([]byte("r"), 1) }, `Reveal rejected \(too late\) by responder `},
		{"reveal early", commands.RevealTooEarly, &AuthorityRevealDeadline, func(s *state) { s.sendRevealToAuthorities([]byte("r"), 1) }, `Reveal rejected \(too early\) by responder `},
		{"sig late", commands.SigTooLate, &PublishConsensusDeadline, func(s *state) { s.sendSigToAuthorities([]byte("s"), 1) }, `Signature rejected \(too late\) by responder `},
		{"sig early", commands.SigTooEarly, &PublishConsensusDeadline, func(s *state) { s.sendSigToAuthorities([]byte("s"), 1) }, `Signature rejected \(too early\) by responder `},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clockLogShortDeadline(t, c.deadline)
			sender, p := clockLogSender(t, c.code)
			sender.Lock()
			c.send(sender)
			sender.Unlock()
			require.Eventually(t, func() bool {
				b, err := os.ReadFile(p)
				return err == nil && regexp.MustCompile(c.line+clockLogPattern).MatchString(string(b))
			}, 10*time.Second, 20*time.Millisecond)
		})
	}
}
