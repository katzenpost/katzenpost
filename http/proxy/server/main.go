// main.go - kaetzchen http proxy daemon
// Copyright (C) 2023 Masala.
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

package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"path"
	"path/filepath"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/http/proxy/common"
	"github.com/katzenpost/katzenpost/http/proxy/server/config"
	"github.com/katzenpost/katzenpost/server/cborplugin"

	"gopkg.in/op/go-logging.v1"
)

type proxy struct {
	allowedHost map[string]struct{}
	log         *logging.Logger
	geo         *geo.Geometry

	write func(cborplugin.Command)
}

func newProxy(log *logging.Logger, host string, geo *geo.Geometry) *proxy {
	p := &proxy{
		allowedHost: make(map[string]struct{}),
		log:         log,
		geo:         geo,
	}
	p.allowedHost[host] = struct{}{}
	return p
}

func (p proxy) OnCommand(cmd cborplugin.Command) error {
	switch r := cmd.(type) {
	case *cborplugin.Request:
		// deserialize the HTTP/1.1 wire-format request from the kaetzchen payload
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewBuffer(r.Payload)))
		if err != nil {
			p.log.Errorf("http.ReadRequest: %s", err)
			return err
		}
		p.log.Debugf("got request for %s", req.URL)
		// make the request
		if _, ok := p.allowedHost[req.URL.Host]; !ok {
			if _, ok := p.allowedHost["*"]; !ok {
				// ignore request or send a http.Response
				p.log.Errorf("invalid AllowedHost: %s", req.Host)
				return errors.New("requested host invalid")
			}
		}
		p.log.Debugf("doing round trip with %s", req.URL)
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			p.log.Errorf("http.Request: %v", req)
			p.log.Errorf("DefaultTransport: %s", err)
			return err
		}
		p.log.Debugf("writing raw response")
		rawResp, err := httputil.DumpResponse(resp, true)
		if err != nil {
			return err
		}

		// check that the respones size is not too large
		if len(rawResp) > p.geo.UserForwardPayloadLength {
			return errors.New("Response exceeds Sphinx Geometry's UserForwardPayloadLength")
		}

		// wrap response in common.Response to indicate length to client
		cr := &common.Response{Payload: rawResp}
		serialized, err := cbor.Marshal(cr)
		if err != nil {
			return err
		}

		p.write(&cborplugin.Response{ID: r.ID, SURB: r.SURB, Payload: serialized})
		return nil
	default:
		p.log.Errorf("OnCommand called with unknown Command type")
		return errors.New("invalid command type")
	}
}

func main() {
	var logLevel string
	var logDir string
	var host string
	var configPath string
	flag.StringVar(&logDir, "log_dir", "", "logging directory")
	flag.StringVar(&logLevel, "log_level", "DEBUG", "logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	flag.StringVar(&host, "host", "*", "wildcard allow proxy to any http.Request.Host")
	flag.StringVar(&configPath, "config", "", "file path to the TOML configuration file")
	flag.Parse()

	if configPath == "" {
		panic("config must be specified")
	}

	cfg, err := config.LoadFile(configPath)
	if err != nil {
		panic(err)
	}

	// Ensure that the log directory exists.
	s, err := os.Stat(logDir)
	if os.IsNotExist(err) {
		fmt.Printf("Log directory '%s' doesn't exist.", logDir)
		os.Exit(1)
	}
	if !s.IsDir() {
		fmt.Println("Log directory must actually be a directory.")
		os.Exit(1)
	}

	// Log to a file.
	logFile := path.Join(logDir, fmt.Sprintf("proxy.%d.log", os.Getpid()))
	logBackend, err := log.New(logFile, logLevel, false)
	if err != nil {
		panic(err)
	}
	serverLog := logBackend.GetLogger("http_proxy")

	// start service
	tmpDir, err := ioutil.TempDir("", "http_proxy")
	if err != nil {
		panic(err)
	}
	socketFile := filepath.Join(tmpDir, fmt.Sprintf("%d.http_proxy.socket", os.Getpid()))

	p := newProxy(serverLog, host, cfg.SphinxGeometry)

	cmdBuilder := new(cborplugin.RequestFactory)
	server := cborplugin.NewServer(serverLog, socketFile, cmdBuilder, p)
	fmt.Printf("%s\n", socketFile)
	server.Accept()
	server.Wait()
	os.Remove(socketFile)
}

func (p *proxy) RegisterConsumer(svr *cborplugin.Server) {
	p.log.Debugf("RegisterConsumer called")
	p.write = svr.Write
}
