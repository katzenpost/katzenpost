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

	"github.com/katzenpost/katzenpost/core/wire"
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

	scheme := wire.DefaultScheme
	key, err := scheme.UnmarshalTextPublicKey([]byte("+YlLke0dvNvCDjtKnUTCsOGg7hQpE3FFtivO5FM6zRs8/AGtbEm74X8JQj3dcos29TCiprAMdU6aLHpnm8gKw2amciXlcawAMApQIQoSsBBkAVlNehZmiWqw+KstbHJsyUL6BpJj/JPUcFM+QSZqo3fBURrstpAOBKddqs6calQ3+ZF9MxI8aV3hzJ3RMSCXB7W3WRNps8LcfIAvWaHyia/nFcpBWVOvDGxVSXmyrBUkALUOkHIDlyso6BKmRB/7RgiSFJfwwaZRKl2GlcNW2KiZUCTL6KlKgoy5mZyCSK9GMonAyIKRaw7zVTK2iLudKoRXFMNdmXfv1VGygWpmNT33C59fa0kScQrgM1S3qizA9waQ5pbeWUcn+7vz141TO7wQ8LAIE6ZlpnWoJ7DFps5jU2fngUyMs88FQiUPqzx8iSkU/GuSMhwqFGpdykk3FGfqVLrcs1im9onOIZyOwW5Pos8dNwFyGbfOqoJldphv2cd+VDvZJIkDq3n3s4+X+n4OtyL6ipEr8AkBFHtPgEm8iA9RhjoOInO3hIPT0sAp2rQ8NxDqegYfSo2uLBuT1m1YAAnu2sHDkDJxWkBMk81X+wBT0qJF9c+vjEDP7HvRYzXgJQv9dgMcoM/WmyzFGZAamLdHiIjk+m+CzKyTFqqCeB4U+z0UcURY0IFj8iNkPFVbUmTzAjO3arNNJp41sjP7Os8RDFMzKQU8ZrEHioeP5E/yE3Pq58gXIZbw1Vb+rDkEQ5LCGB/W9rHEWb8tyzoyFSfvDB8TM24oKnYFZcmnUMRLfFXSqSvYqwpiOTP09D5zgQ6QJB4ZZXy1eIL0ZDkVtEPqm1eySytgl4kvBG+IhrfISk678rhG+7oEmC5vSjir1mEoowaQphzgZSIxkgTW6k3o5j2h1wJIMSKAFpULNFJuKT3aZonP6TctgVLzYsvRyYBhUwfpt27wFM0RphtPibbwBhvarJxBMr+bQxSU6sM9ebKJOwU863sPt0L5AxzZ9mBJioeO1MZIM5QoO3CJFGmDtTBKZTOcjFpqRzNGukRxwcGBFaEpaquDNQZhU2ilDJhedIV390i86UuIFFliNBXCiF/69r9qUyc5Gct+Gq9KkXnM56MOHBW9eEXgxkBSLJew02PhIq9zIm4AZmztI5VuE3oeBhE5lDVmK4BYtiV20yhmuzIglV9XUK1EmcZ0InCXioR6F78ZyTrf6kH2trJTp1mfyyOlOlyaJhkwRql5CDtKJFa4smJ+l0TPzL4N5yANg7uJp1Z+wV6tCy/0w222WpSld4saSC/w4Z+hKDIAd1zCUKpd6CB0DEzAGs2NgFCrxWJ0VFW4bJIk7Elh6ETo5qmXVrqI0T9mAWJygzlgaLHTJzUIQmFPGTjFqVeIdq4I4kozA2go6wNqGS8/GjdnM3tEKkWUpH26vEPy2h3scANW5AayfDt09skORpvPKn3ftivXzJRe0UlNm0skeA62QMers8WZs3WfFXDku6i9aWh/mAZNZDvjPB/KdB30GQs38Sfh+aGHMyyvtZSdMwZ+4Btpcg7LirNJyTYPoEILFyleya/PQreNCHRIAQVNKKgj2VtieS0vYa9ZM+xy2IJJxxWtur6ww/AU6Q=="))
	if err != nil {
		t.Fatal(err)
	}
	u := []byte("testuser")
	if !e.IsValid(u, key) {
		t.Errorf("user should be valid")
	}

}

func TestIsNotValid(t *testing.T) {
	ts := httpMock("{\"isvalid\": false}")
	defer ts.Close()

	e, _ := New(ts.URL)

	scheme := wire.DefaultScheme
	key, err := scheme.UnmarshalTextPublicKey([]byte("+YlLke0dvNvCDjtKnUTCsOGg7hQpE3FFtivO5FM6zRs8/AGtbEm74X8JQj3dcos29TCiprAMdU6aLHpnm8gKw2amciXlcawAMApQIQoSsBBkAVlNehZmiWqw+KstbHJsyUL6BpJj/JPUcFM+QSZqo3fBURrstpAOBKddqs6calQ3+ZF9MxI8aV3hzJ3RMSCXB7W3WRNps8LcfIAvWaHyia/nFcpBWVOvDGxVSXmyrBUkALUOkHIDlyso6BKmRB/7RgiSFJfwwaZRKl2GlcNW2KiZUCTL6KlKgoy5mZyCSK9GMonAyIKRaw7zVTK2iLudKoRXFMNdmXfv1VGygWpmNT33C59fa0kScQrgM1S3qizA9waQ5pbeWUcn+7vz141TO7wQ8LAIE6ZlpnWoJ7DFps5jU2fngUyMs88FQiUPqzx8iSkU/GuSMhwqFGpdykk3FGfqVLrcs1im9onOIZyOwW5Pos8dNwFyGbfOqoJldphv2cd+VDvZJIkDq3n3s4+X+n4OtyL6ipEr8AkBFHtPgEm8iA9RhjoOInO3hIPT0sAp2rQ8NxDqegYfSo2uLBuT1m1YAAnu2sHDkDJxWkBMk81X+wBT0qJF9c+vjEDP7HvRYzXgJQv9dgMcoM/WmyzFGZAamLdHiIjk+m+CzKyTFqqCeB4U+z0UcURY0IFj8iNkPFVbUmTzAjO3arNNJp41sjP7Os8RDFMzKQU8ZrEHioeP5E/yE3Pq58gXIZbw1Vb+rDkEQ5LCGB/W9rHEWb8tyzoyFSfvDB8TM24oKnYFZcmnUMRLfFXSqSvYqwpiOTP09D5zgQ6QJB4ZZXy1eIL0ZDkVtEPqm1eySytgl4kvBG+IhrfISk678rhG+7oEmC5vSjir1mEoowaQphzgZSIxkgTW6k3o5j2h1wJIMSKAFpULNFJuKT3aZonP6TctgVLzYsvRyYBhUwfpt27wFM0RphtPibbwBhvarJxBMr+bQxSU6sM9ebKJOwU863sPt0L5AxzZ9mBJioeO1MZIM5QoO3CJFGmDtTBKZTOcjFpqRzNGukRxwcGBFaEpaquDNQZhU2ilDJhedIV390i86UuIFFliNBXCiF/69r9qUyc5Gct+Gq9KkXnM56MOHBW9eEXgxkBSLJew02PhIq9zIm4AZmztI5VuE3oeBhE5lDVmK4BYtiV20yhmuzIglV9XUK1EmcZ0InCXioR6F78ZyTrf6kH2trJTp1mfyyOlOlyaJhkwRql5CDtKJFa4smJ+l0TPzL4N5yANg7uJp1Z+wV6tCy/0w222WpSld4saSC/w4Z+hKDIAd1zCUKpd6CB0DEzAGs2NgFCrxWJ0VFW4bJIk7Elh6ETo5qmXVrqI0T9mAWJygzlgaLHTJzUIQmFPGTjFqVeIdq4I4kozA2go6wNqGS8/GjdnM3tEKkWUpH26vEPy2h3scANW5AayfDt09skORpvPKn3ftivXzJRe0UlNm0skeA62QMers8WZs3WfFXDku6i9aWh/mAZNZDvjPB/KdB30GQs38Sfh+aGHMyyvtZSdMwZ+4Btpcg7LirNJyTYPoEILFyleya/PQreNCHRIAQVNKKgj2VtieS0vYa9ZM+xy2IJJxxWtur6ww/AU6Q=="))
	if err != nil {
		t.Fatal(err)
	}

	u := []byte("testuser")
	if e.IsValid(u, key) {
		t.Errorf("user should not be valid")
	}
}

func httpMock(response string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(response))
	}))
}
