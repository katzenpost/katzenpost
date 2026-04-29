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
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/carlmjohnson/versioninfo"
	cbor "github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/hpqc/hash"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/quic/proxy/common"
)

var (
	cfgFile  = flag.String("cfg", "proxy.toml", "thin client config file")
	epName   = flag.String("ep", "http", "endpoint name")
	logLevel = flag.String("log_level", "DEBUG", "logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	port     = flag.Int("port", 8080, "listener address")
	retry    = flag.Int("retry", -1, "limit number of reconnection attempts")
	delay    = flag.Int("delay", 30, "time to wait between connection attempts (seconds)>")
)

// getThinClient connects to the client2 daemon and returns a ThinClient
func getThinClient(cfgFile string) (*thin.ThinClient, error) {
	cfg, err := thin.LoadFile(cfgFile)
	if err != nil {
		return nil, err
	}

	logging := &config.Logging{
		Level: *logLevel,
	}
	client := thin.NewThinClient(cfg, logging)

	retries := 0
	for {
		err = client.Dial()
		switch err {
		case nil:
			return client, nil
		default:
			<-time.After(time.Duration(*delay) * time.Second)
			if retries == *retry {
				return nil, errors.New("failed to connect within retry limit")
			}
		}
		retries++
	}
}

type kttp struct {
	client *thin.ThinClient
	log    *logging.Logger
}

func (k *kttp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d, err := k.client.GetService(*epName)
	if err != nil {
		k.log.Errorf("Err getting service: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// serialize the http request
	buf, err := httputil.DumpRequest(r, true)
	if err != nil {
		k.log.Errorf("Err dumping request: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// send the http request
	destNode := hash.Sum256(d.MixDescriptor.IdentityKey)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	response, err := k.client.BlockingSendMessage(ctx, buf, &destNode, d.RecipientQueueID)
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
	flag.Parse()
	client, err := getThinClient(*cfgFile)
	if err != nil {
		panic(err)
	}
	defer client.Close()

	clientLog := client.GetLogger("http_proxy")
	clientLog.Noticef("Katzenpost http-proxy-client version: %s", versioninfo.Short())
	clientLog.Notice("Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.")

	addr := fmt.Sprintf(":%d", *port)
	handler := &kttp{client: client, log: clientLog}
	http.ListenAndServe(addr, handler)
}
