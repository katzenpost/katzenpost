// hybrid_test.go - hybrid certificate tests.
// Copyright (C) 2022  David Stainton.
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

package cert

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/crypto/sign/eddsa"
	"github.com/katzenpost/katzenpost/core/crypto/sign/hybrid"
	"github.com/katzenpost/katzenpost/core/crypto/sign/sphincsplus"
)

func TestHybridCertificate(t *testing.T) {
	scheme := hybrid.NewScheme(eddsa.Scheme, sphincsplus.Scheme)
	signingPrivKey, signingPubKey := scheme.NewKeypair()

	// expires 600 years after unix epoch
	expiration := time.Unix(0, 0).AddDate(600, 0, 0).Unix()

	toSign := []byte("hello this is a message")
	certificate, err := Sign(signingPrivKey, signingPubKey, toSign, expiration)
	require.NoError(t, err)

	mesg, err := Verify(signingPubKey, certificate)
	require.NoError(t, err)
	require.NotNil(t, mesg)
	require.Equal(t, mesg, toSign)
}
