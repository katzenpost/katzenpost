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

	"github.com/katzenpost/core/crypto/ecdh"
)

func TestExists(t *testing.T) {
	ts := httpMock("{\"exists\": true}")
	defer ts.Close()

	e, _ := New(ts.URL)

	u := []byte("testuser")
	if !e.Exists(u) {
		t.Errorf("user expected to exist")
	}
}

func TestNotExists(t *testing.T) {
	ts := httpMock("{\"exists\": false}")
	defer ts.Close()

	e, _ := New(ts.URL)

	u := []byte("testuser")
	if e.Exists(u) {
		t.Errorf("user should not exist")
	}
}

func TestIsValid(t *testing.T) {
	ts := httpMock("{\"isvalid\": true}")
	defer ts.Close()

	e, _ := New(ts.URL)

	key := ecdh.PublicKey{}
	key.FromString("B2E3ABEE63BCF7BAC4DCD232C4852F90FA458B4269B673C76C4DE02D0D24402C")
	u := []byte("testuser")
	if !e.IsValid(u, &key) {
		t.Errorf("user should be valid")
	}
}

func TestIsNotValid(t *testing.T) {
	ts := httpMock("{\"isvalid\": false}")
	defer ts.Close()

	e, _ := New(ts.URL)

	key := ecdh.PublicKey{}
	key.FromString("B2E3ABEE63BCF7BAC4DCD232C4852F90FA458B4269B673C76C4DE02D0D24402C")
	u := []byte("testuser")
	if e.IsValid(u, &key) {
		t.Errorf("user should not be valid")
	}
}

func httpMock(response string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(response))
	}))
}
