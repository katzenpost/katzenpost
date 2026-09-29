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
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"path"
	"path/filepath"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/spf13/cobra"
	"gopkg.in/op/go-logging.v1"

	kpcommon "github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/quic/proxy/common"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

type proxyServerConfig struct {
	host     string
	logDir   string
	logLevel string
}

type proxy struct {
	allowedHost map[string]struct{}
	log         *logging.Logger

	write func(cborplugin.Command)
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

		/*
			if len(rawResp) > 10240 {// where do we learn our maximum payload size ?
				return nil, errors.New("Response is too long")
			}
		*/

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
	cmd := newRootCommand()
	cmd.SetArgs(normalizeLegacyArgs(cmd, os.Args[1:]))
	kpcommon.ExecuteWithFang(cmd)
}

func normalizeLegacyArgs(cmd *cobra.Command, args []string) []string {
	return kpcommon.NormalizeLegacyLongFlags(cmd, args, "log_dir", "log_level", "host")
}

func newRootCommand() *cobra.Command {
	var cfg proxyServerConfig
	cmd := &cobra.Command{
		Use:   "http-proxy-server",
		Short: "Katzenpost HTTP proxy service plugin",
		Run: func(cmd *cobra.Command, args []string) {
			runProxyServer(cfg)
		},
	}
	cmd.Flags().StringVar(&cfg.logDir, "log_dir", "", "logging directory")
	cmd.Flags().StringVar(&cfg.logLevel, "log_level", "DEBUG", "logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	cmd.Flags().StringVar(&cfg.host, "host", "*", "wildcard allow proxy to any http.Request.Host")
	return cmd
}

func runProxyServer(cfg proxyServerConfig) {
	// Ensure that the log directory exists.
	s, err := os.Stat(cfg.logDir)
	if os.IsNotExist(err) {
		cborplugin.FailStartup("http-proxy-server", fmt.Errorf("log directory %q doesn't exist", cfg.logDir))
	}
	if !s.IsDir() {
		cborplugin.FailStartup("http-proxy-server", fmt.Errorf("log directory %q is not a directory", cfg.logDir))
	}

	// Log to a file.
	logFile := path.Join(cfg.logDir, fmt.Sprintf("proxy.%d.log", os.Getpid()))
	logBackend, err := log.New(logFile, cfg.logLevel, false)
	if err != nil {
		cborplugin.FailStartup("http-proxy-server", err)
	}
	serverLog := logBackend.GetLogger("http_proxy")
	serverLog.Noticef("Katzenpost http-proxy-server version: %s", kpcommon.Version())
	serverLog.Notice("Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.")

	// start service
	tmpDir, err := ioutil.TempDir("", "http_proxy")
	if err != nil {
		cborplugin.FailStartup("http-proxy-server", err)
	}
	socketFile := filepath.Join(tmpDir, fmt.Sprintf("%d.http_proxy.socket", os.Getpid()))

	p := &proxy{allowedHost: make(map[string]struct{}), log: serverLog}
	p.allowedHost[cfg.host] = struct{}{}

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
