// externuserdb.go - extern REST API backed Katzenpost server user database.
// Copyright (C) 2017  Kali Kaneko.
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
	"errors"
	"net/http"
	"net/url"

	"github.com/ugorji/go/codec"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/pem"

	"github.com/katzenpost/katzenpost/server/userdb"
)

var (
	errCantModify   = errors.New("Not implemented: External authentication is enabled, you can not modify users")
	errNotSupported = errors.New("Not implemented: Support not implemented yet")
	jsonHandle      = &codec.JsonHandle{}
)

type externAuth struct {
	provider string
	scheme   kem.Scheme
}

func (e *externAuth) doPost(endpoint string, data url.Values) bool {
	uri := e.provider + "/" + endpoint
	rsp, err := http.PostForm(uri, data)
	if err != nil {
		return false
	}
	defer rsp.Body.Close()

	response := map[string]bool{}
	d := codec.NewDecoder(rsp.Body, jsonHandle)
	if err = d.Decode(&response); err != nil {
		return false
	}

	return rsp.StatusCode == 200 && response[endpoint]
}

func (e *externAuth) IsValid(u []byte, k kem.PublicKey) bool {
	form := url.Values{"user": {string(u)}, "key": {pem.ToPublicPEMString(k)}}
	return e.doPost("isvalid", form)
}

func (e *externAuth) Exists(u []byte) bool {
	form := url.Values{"user": {string(u)}}
	return e.doPost("exists", form)
}

func (e *externAuth) Add(u []byte, k kem.PublicKey, update bool) error {
	return errCantModify
}

func (e *externAuth) Link(u []byte) (kem.PublicKey, error) {
	return nil, errNotSupported
}

func (e *externAuth) SetIdentity(u []byte, k kem.PublicKey) error {
	return errNotSupported
}

func (e *externAuth) Identity(u []byte) (kem.PublicKey, error) {
	endpoint := "getidkey"
	uri := e.provider + "/" + endpoint
	form := url.Values{"user": {string(u)}}
	rsp, err := http.PostForm(uri, form)
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()

	if rsp.StatusCode == 200 {
		response := map[string]string{}
		d := codec.NewDecoder(rsp.Body, jsonHandle)
		if err = d.Decode(&response); err != nil {
			return nil, err
		}

		if idkey, ok := response[endpoint]; ok {
			pubKey, err := pem.FromPublicPEMString(idkey, e.scheme)
			if err != nil {
				return nil, err
			}
			if err == nil {
				return pubKey, nil
			}
		}
	}
	return nil, userdb.ErrNoIdentity
}

func (e *externAuth) Remove(u []byte) error {
	return errCantModify
}

func (e *externAuth) Close() {
}

// New creates an external user database with the given provider
func New(provider string, scheme kem.Scheme) (userdb.UserDB, error) {
	return &externAuth{
		provider: provider,
		scheme:   scheme,
	}, nil
}
