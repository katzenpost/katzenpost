// main.go - client proxy daemon
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
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/hpqc/hash"
	"github.com/spf13/cobra"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
	kpcommon "github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/quic/proxy/common"
)

type proxyClientConfig struct {
	cfgFile  string
	epName   string
	logLevel string
	listen   string
	port     int
	retry    int
	delay    int
}

// getThinClient connects to the client daemon and returns a ThinClient
func getThinClient(cmdCfg proxyClientConfig) (*thin.ThinClient, error) {
	cfg, err := thin.LoadFile(cmdCfg.cfgFile)
	if err != nil {
		return nil, err
	}

	logging := &config.Logging{
		Level: cmdCfg.logLevel,
	}
	client := thin.NewThinClient(cfg, logging)

	retries := 0
	for {
		err = client.Dial()
		switch err {
		case nil:
			return client, nil
		default:
			<-time.After(time.Duration(cmdCfg.delay) * time.Second)
			if retries == cmdCfg.retry {
				return nil, errors.New("failed to connect within retry limit")
			}
		}
		retries++
	}
}

type kttp struct {
	log  *logging.Logger
	send func(ctx context.Context, request []byte) ([]byte, error)
}

func (k *kttp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// serialize the http request
	buf, err := httputil.DumpRequest(r, true)
	if err != nil {
		k.log.Errorf("Err dumping request: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// send the http request
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	response, err := k.send(ctx, buf)
	if err != nil {
		// send http error response
		k.log.Errorf("Err sending message: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// decode payload from response
	proxyResponse := &common.Response{}
	_, err = cbor.UnmarshalFirst(response, proxyResponse)
	if err != nil {
		// send http error response
		k.log.Errorf("Err unmarshalling kaetzchen response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// return the http response
	responseReader := bufio.NewReader(bytes.NewBuffer(proxyResponse.Payload))
	resp, err := http.ReadResponse(responseReader, r)
	if err != nil {
		// send http error response
		k.log.Errorf("Err parsing http response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	defer resp.Body.Close()
	_, err = io.Copy(w, resp.Body)
	// log err
	if err != nil {
		k.log.Errorf("Err proxying: %v", err)
	}
}

func main() {
	cmd := newRootCommand()
	cmd.SetArgs(normalizeLegacyArgs(cmd, os.Args[1:]))
	kpcommon.ExecuteWithFang(cmd)
}

func normalizeLegacyArgs(cmd *cobra.Command, args []string) []string {
	return kpcommon.NormalizeLegacyLongFlags(cmd, args, "cfg", "ep", "log_level", "port", "retry", "delay")
}

func newRootCommand() *cobra.Command {
	var cfg proxyClientConfig
	cmd := &cobra.Command{
		Use:   "http-proxy-client",
		Short: "Katzenpost HTTP proxy client",
		Run: func(cmd *cobra.Command, args []string) {
			runProxyClient(cfg)
		},
	}
	cmd.Flags().StringVar(&cfg.cfgFile, "cfg", "proxy.toml", "thin client config file")
	cmd.Flags().StringVar(&cfg.epName, "ep", "http", "endpoint name")
	cmd.Flags().StringVar(&cfg.logLevel, "log_level", "NOTICE", "logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	cmd.Flags().StringVar(&cfg.listen, "listen", "127.0.0.1:8080", "address to listen on")
	cmd.Flags().IntVar(&cfg.port, "port", 0, "port to listen on, on 127.0.0.1")
	cmd.Flags().MarkDeprecated("port", "use --listen 127.0.0.1:<port>")
	cmd.Flags().IntVar(&cfg.retry, "retry", -1, "limit number of reconnection attempts")
	cmd.Flags().IntVar(&cfg.delay, "delay", 30, "time to wait between connection attempts (seconds)>")
	return cmd
}

func runProxyClient(cfg proxyClientConfig) {
	client, err := getThinClient(cfg)
	if err != nil {
		panic(err)
	}
	defer client.Close()

	clientLog := client.GetLogger("http_proxy")
	clientLog.Noticef("Katzenpost http-proxy-client version: %s", kpcommon.Version())
	clientLog.Notice("Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.")

	handler := &kttp{log: clientLog, send: func(ctx context.Context, request []byte) ([]byte, error) {
		d, err := client.GetService(cfg.epName)
		if err != nil {
			return nil, err
		}
		destNode := hash.Sum256(d.MixDescriptor.IdentityKey)
		return client.BlockingSendMessage(ctx, request, &destNode, d.RecipientQueueID)
	}}
	newHTTPServer(cfg, handler).ListenAndServe()
}

func newHTTPServer(cfg proxyClientConfig, handler http.Handler) *http.Server {
	addr := cfg.listen
	if cfg.port != 0 {
		addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.port))
	}
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
}
