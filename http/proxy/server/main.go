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
	"net/url"
	"os"
	"path"
	"path/filepath"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/server/cborplugin"
	"gopkg.in/op/go-logging.v1"
)

type proxy struct {
	allowedHost map[string]struct{}
	log         *logging.Logger
}

func (p proxy) OnCommand(cmd cborplugin.Command) (cborplugin.Command, error) {
	switch r := cmd.(type) {
	case *cborplugin.Request:
		// deserialize the HTTP/1.1 wire-format request from the kaetzchen payload
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewBuffer(r.Payload)))
		if err != nil {
			p.log.Errorf("http.ReadRequest: %s", err)
			return nil, err
		}
		// make the request
		if _, ok := p.allowedHost[req.Host]; !ok {
			if _, ok := p.allowedHost["*"]; !ok {
				// ignore request or send a http.Response
				err := errors.New("requested host invalid")
				p.log.Errorf("AllowedHost: %s", err)
				return nil, err
			}
		}
		// http.ReadRequest does not populate http.Request.URL
		u, err := url.Parse("http://" + req.Host)
		if err != nil {
			return nil, err
		}
		req.URL = u
		p.log.Debugf("doing round trip with %s", req.URL)
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			p.log.Errorf("http.Request: %v", req)
			p.log.Errorf("DefaultTransport: %s", err)
			return nil, err
		}
		p.log.Debugf("writing raw response")
		rawResp := new(bytes.Buffer)
		resp.Write(rawResp)

		/*
			if len(rawResp.Bytes()) > 10240 {// where do we learn our maximum payload size ?
				return nil, errors.New("Response is too long")
			}
		*/
		return &cborplugin.Response{Payload: rawResp.Bytes()}, nil
	default:
		p.log.Errorf("OnCommand called with unknown Command type")
		return nil, errors.New("invalid command type")
	}
}

func main() {
	var logLevel string
	var logDir string
	var host string
	flag.StringVar(&logDir, "log_dir", "", "logging directory")
	flag.StringVar(&logLevel, "log_level", "DEBUG", "logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	flag.StringVar(&host, "host", "*", "wildcard allow proxy to any http.Request.Host")
	flag.Parse()

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

	p := proxy{allowedHost: make(map[string]struct{}), log: serverLog}
	// TODO: support csv host arg
	p.allowedHost[host] = struct{}{}

	cmdBuilder := new(cborplugin.RequestFactory)
	server := cborplugin.NewServer(serverLog, socketFile, cmdBuilder, p)
	fmt.Printf("%s\n", socketFile)
	server.Accept()
	server.Wait()
	os.Remove(socketFile)
}

func (p proxy) RegisterConsumer(svr *cborplugin.Server) {
	p.log.Debugf("RegisterConsumer called")
}
