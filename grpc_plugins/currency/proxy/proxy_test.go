// proxy_tests.go - Katzenpost currency serice plugin proxy tests
// Copyright (C) 2018  David Stainton.
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

package proxy

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/katzenpost/server_plugins/grpc_plugins/currency/common"
	"github.com/katzenpost/server_plugins/grpc_plugins/currency/config"
	"github.com/stretchr/testify/assert"
)

const (
	zcashSendVersion = 0
)

type zcashSendRequest struct {
	Version int
	Tx      string
}

func TestProxy(t *testing.T) {
	assert := assert.New(t)

	logDir, err := ioutil.TempDir("", "example")
	assert.NoError(err)
	defer os.RemoveAll(logDir) // clean up
	content := []byte(fmt.Sprintf(`
Ticker = "ZEC"
RPCUser = "rpcuser"
RPCPass = "rpcsecretpassword"
RPCURL = "http://127.0.0.1:18232/"
LogDir = "%s"
LogLevel = "DEBUG"
`, logDir))
	tmpfn := filepath.Join(logDir, "currency.toml")
	err = ioutil.WriteFile(tmpfn, content, 0666)
	assert.NoError(err)

	cfg, err := config.LoadFile(tmpfn)
	assert.NoError(err)
	p, err := New(cfg)
	assert.NoError(err)

	hexBlob := "deadbeef"
	currencyRequest := common.NewRequest(cfg.Ticker, hexBlob)
	zcashRequest := currencyRequest.ToJson()
	id := uint64(123)
	hasSURB := true
	reply, err := p.OnRequest(id, zcashRequest, hasSURB)
	assert.NoError(err)

	t.Logf("reply: %s", reply)
}
