// externuserdb_test.go - extern REST API backed Katzenpost server user database.
// Copyright (C) 2017  Ruben Pollan.
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

// Package externuserdb implements the Katzenpost server user database with
// http calls to a external authorization source (expected to run in localhost).

package externuserdb

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem/schemes"
)

var testingSchemeName = "x25519"
var testingScheme = schemes.ByName(testingSchemeName)

func TestExists(t *testing.T) {
	t.Parallel()
	ts := httpMock("{\"exists\": true}")
	defer ts.Close()

	e, _ := New(ts.URL, testingScheme)

	u := []byte("testuser")
	if !e.Exists(u) {
		t.Errorf("user expected to exist")
	}
}

func TestNotExists(t *testing.T) {
	t.Parallel()
	ts := httpMock("{\"exists\": false}")
	defer ts.Close()

	e, _ := New(ts.URL, testingScheme)

	u := []byte("testuser")
	if e.Exists(u) {
		t.Errorf("user should not exist")
	}
}

func TestIsValid(t *testing.T) {
	t.Parallel()
	ts := httpMock("{\"isvalid\": true}")
	defer ts.Close()

	e, _ := New(ts.URL, testingScheme)

	key, _, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)

	u := []byte("testuser")
	require.True(t, e.IsValid(u, key))
}

func TestIsNotValid(t *testing.T) {
	t.Parallel()
	ts := httpMock("{\"isvalid\": false}")
	defer ts.Close()

	e, _ := New(ts.URL, testingScheme)

	key, _, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)

	u := []byte("testuser")
	require.False(t, e.IsValid(u, key))
}

func httpMock(response string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(response))
	}))
}
