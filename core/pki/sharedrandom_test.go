// sharedrandom_test.go - Voting authority state machine tests.
// Copyright (C) 2022  Masala, David Stainton
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

package pki

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSharedRandomVerify(t *testing.T) {
	require := require.New(t)
	srv := new(SharedRandom)
	commit, err := srv.Commit(1234)
	require.NoError(err, "wtf")
	require.True(len(commit) == SharedRandomLength)
	srv.SetCommit(commit)
	require.True(bytes.Equal(commit, srv.GetCommit()))
	require.True(bytes.Equal(commit, srv.GetCommit()))
	reveal := srv.Reveal()
	require.True(len(reveal) == SharedRandomLength)
	require.True(srv.Verify(reveal))
}

func TestSharedRandomCommit(t *testing.T) {
	require := require.New(t)
	srv := new(SharedRandom)
	commit, err := srv.Commit(1234)
	require.NoError(err, "wtf")
	require.True(len(commit) == SharedRandomLength)
}

func TestSharedRandomSetCommit(t *testing.T) {
	require := require.New(t)
	srv := new(SharedRandom)
	commit, err := srv.Commit(1234)
	require.NoError(err, "wtf")
	srv.SetCommit(commit)
	require.True(bytes.Equal(commit, srv.GetCommit()))
}
