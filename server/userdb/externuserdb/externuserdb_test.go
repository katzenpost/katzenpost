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

	"github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/stretchr/testify/require"
)

func TestExists(t *testing.T) {
	t.Parallel()
	ts := httpMock("{\"exists\": true}")
	defer ts.Close()

	e, _ := New(ts.URL)

	u := []byte("testuser")
	if !e.Exists(u) {
		t.Errorf("user expected to exist")
	}
}

func TestNotExists(t *testing.T) {
	t.Parallel()
	ts := httpMock("{\"exists\": false}")
	defer ts.Close()

	e, _ := New(ts.URL)

	u := []byte("testuser")
	if e.Exists(u) {
		t.Errorf("user should not exist")
	}
}

func TestIsValid(t *testing.T) {
	t.Parallel()
	ts := httpMock("{\"isvalid\": true}")
	defer ts.Close()

	e, _ := New(ts.URL)

	scheme := wire.DefaultScheme
	key, err := pem.FromPublicPEMString(
		`-----BEGIN KYBER768-X25519 PUBLIC KEY-----
NPSZCu7X5IlqecF8KNcDO9avZPWA6F5EoJn0Lv/4hBsHsYSVuUQJxhP1jFH47Ab0
xmOJlUMgJBlj42nVVBvNsqJCJmkjiSJbi7EVoXCsSIz8fJRPB1ZN9zPNyhdMwkuH
ESVW56/s3EVBJFbQiUn47K3K5i3hMKRdNWb8JYQgxCW1USroiM56hCp+aio/x5oc
GHTSYXd+0ZOGV2JnQoCGADzlA6C9xShw+FKaPGT/FFg0sTT2FpxZtVu9g2rt0owq
lo23m0jbiRAoYymioVStvGFQoSrCA5zRYonPp0HeB28pcVwthrnKZzFA2YpwNYF7
5ABawaV7IVMte7bSWpxwfDXrYr4yqCMHm7kQQF3LNEEJ6omGOYK5UDvcp3StSBxQ
d0TPkTEt6rho2VMQQMdn01Br4QtXEbEvGT5ApcMqJpvsU6aujAtDc0uCt7djZ5wr
YliIZwkDJrZRJDuupJJAEVL8BbuPNytPsz5ipm90CxMdh5Xseyvy4C/PSpM/Fs52
dmWpZGL008PSCq/Cy0tOw3bJVjz6IaS1WnbDoGDSAAn3qjRPV4t8IJhrm0agiKuV
FyDi0Qnc3KmlgFECOVgLFnql3ALxoXJjA5QBZjGwuaMw2ZwzqkbCOkcjUxvHG05a
853w/I/SWZM0YKRdiJL+mD3UxqSOwlEjkpXbx7vNLHpaKTpokzPuyZ2m6wbuhqnz
VyxtQ2pqXEKTg31ZZnM2EcWLCbgVljV8C2XFwBijMbK4Jw7SxbT62E2g0VvkOQyN
p5xNkqO+5W+cF7qowwIOWLooJckBNS+elIKxEr8Og3v+kmJZTB7wCS68IKytSk1r
cb60p6D7cT9G5Lq9U5HQBWS/RoE9NlHpl1jKx04oKApS2yZsKHuWxxAwYnt3RCIx
Q6uCMoBJN0E3oFOIBrjGMkooVAs/BVjpoavTXGY06wdt9ak2xg7p7Li5BbemuGHV
xy1/Sw72sDGValym3HND55GqyTqj5ZaCaLV35gId+rROiJ60HA2oUoixIx4toRCu
SEMUgZxtZYKSGFBa88bTWCcKdJCnYRV3jKzHKmyzKJieO7I2J63f0ELVhHLvaUxo
eUvcYXS1vAKxBaBLQ1XT1XogWLUOEwhuO8N4bEXL4BDV6x+Aei0J6qdWs3kWrDR2
l5xMdpB02xrTrL1aAsYTpcZrkZEcA20yljK+ZmGt2qdWsGRPqEWjqhOkdnwiSYpI
m818W84YWshbYUhrI5dxN8CdSSbo4bm8zDot4D0IGYniNCUls7UmpZ0pI8yLWAAz
87oSoMpIKm+o7H4TNrMczAKrdi53wQyUKrRVZc4pupxclGOwxDOhszQroRgeJ2Hn
A0IM8hub5RBnOCvMgWx7ObvOVo5olJv+gYeKO8or4c7ierzdQxxpEryhBGPO/Gfg
eQTkmMwHsRJC+zkhhonrOJtcWQ4RqTXUu4XF1lWQ902Hg5A+RA1xh6bQCYNAqGhy
ZD+wWXnwaLe/mVdrZxCBZyI+cbsYcLoJJb0MegeKkaT1Vm8xd3o2Z0jCEcdwRzaf
PFtb46IeQLbgSGEJlaKkwHOCdh7jYA5ZRRtxdas3tqTT+YG3i2+SsBbfrfR3Rgkw
maq0njLOi0ygcS1uzSDzKg==
-----END KYBER768-X25519 PUBLIC KEY-----`, scheme)

	if err != nil {
		t.Fatal(err)
	}
	u := []byte("testuser")
	require.True(t, e.IsValid(u, key))
}

func TestIsNotValid(t *testing.T) {
	t.Parallel()
	ts := httpMock("{\"isvalid\": false}")
	defer ts.Close()

	e, _ := New(ts.URL)

	scheme := wire.DefaultScheme
	key, err := pem.FromPublicPEMString(`
-----BEGIN KYBER768-X25519 PUBLIC KEY-----
NPSZCu7X5IlqecF8KNcDO9avZPWA6F5EoJn0Lv/4hBsHsYSVuUQJxhP1jFH47Ab0
xmOJlUMgJBlj42nVVBvNsqJCJmkjiSJbi7EVoXCsSIz8fJRPB1ZN9zPNyhdMwkuH
ESVW56/s3EVBJFbQiUn47K3K5i3hMKRdNWb8JYQgxCW1USroiM56hCp+aio/x5oc
GHTSYXd+0ZOGV2JnQoCGADzlA6C9xShw+FKaPGT/FFg0sTT2FpxZtVu9g2rt0owq
lo23m0jbiRAoYymioVStvGFQoSrCA5zRYonPp0HeB28pcVwthrnKZzFA2YpwNYF7
5ABawaV7IVMte7bSWpxwfDXrYr4yqCMHm7kQQF3LNEEJ6omGOYK5UDvcp3StSBxQ
d0TPkTEt6rho2VMQQMdn01Br4QtXEbEvGT5ApcMqJpvsU6aujAtDc0uCt7djZ5wr
YliIZwkDJrZRJDuupJJAEVL8BbuPNytPsz5ipm90CxMdh5Xseyvy4C/PSpM/Fs52
dmWpZGL008PSCq/Cy0tOw3bJVjz6IaS1WnbDoGDSAAn3qjRPV4t8IJhrm0agiKuV
FyDi0Qnc3KmlgFECOVgLFnql3ALxoXJjA5QBZjGwuaMw2ZwzqkbCOkcjUxvHG05a
853w/I/SWZM0YKRdiJL+mD3UxqSOwlEjkpXbx7vNLHpaKTpokzPuyZ2m6wbuhqnz
VyxtQ2pqXEKTg31ZZnM2EcWLCbgVljV8C2XFwBijMbK4Jw7SxbT62E2g0VvkOQyN
p5xNkqO+5W+cF7qowwIOWLooJckBNS+elIKxEr8Og3v+kmJZTB7wCS68IKytSk1r
cb60p6D7cT9G5Lq9U5HQBWS/RoE9NlHpl1jKx04oKApS2yZsKHuWxxAwYnt3RCIx
Q6uCMoBJN0E3oFOIBrjGMkooVAs/BVjpoavTXGY06wdt9ak2xg7p7Li5BbemuGHV
xy1/Sw72sDGValym3HND55GqyTqj5ZaCaLV35gId+rROiJ60HA2oUoixIx4toRCu
SEMUgZxtZYKSGFBa88bTWCcKdJCnYRV3jKzHKmyzKJieO7I2J63f0ELVhHLvaUxo
eUvcYXS1vAKxBaBLQ1XT1XogWLUOEwhuO8N4bEXL4BDV6x+Aei0J6qdWs3kWrDR2
l5xMdpB02xrTrL1aAsYTpcZrkZEcA20yljK+ZmGt2qdWsGRPqEWjqhOkdnwiSYpI
m818W84YWshbYUhrI5dxN8CdSSbo4bm8zDot4D0IGYniNCUls7UmpZ0pI8yLWAAz
87oSoMpIKm+o7H4TNrMczAKrdi53wQyUKrRVZc4pupxclGOwxDOhszQroRgeJ2Hn
A0IM8hub5RBnOCvMgWx7ObvOVo5olJv+gYeKO8or4c7ierzdQxxpEryhBGPO/Gfg
eQTkmMwHsRJC+zkhhonrOJtcWQ4RqTXUu4XF1lWQ902Hg5A+RA1xh6bQCYNAqGhy
ZD+wWXnwaLe/mVdrZxCBZyI+cbsYcLoJJb0MegeKkaT1Vm8xd3o2Z0jCEcdwRzaf
PFtb46IeQLbgSGEJlaKkwHOCdh7jYA5ZRRtxdas3tqTT+YG3i2+SsBbfrfR3Rgkw
maq0njLOi0ygcS1uzSDzKg==
-----END KYBER768-X25519 PUBLIC KEY-----
`, scheme)
	if err != nil {
		t.Fatal(err)
	}

	u := []byte("testuser")
	require.False(t, e.IsValid(u, key))
}

func httpMock(response string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(response))
	}))
}
