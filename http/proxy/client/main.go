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
	cbor "github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/http/proxy/common"
	"gopkg.in/op/go-logging.v1"

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
)

var (
	cfgFile  = flag.String("cfg", "proxy.toml", "config file")
	epName   = flag.String("ep", "quic", "endpoint name")
	logLevel = flag.String("log_level", "DEBUG", "logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	port     = flag.Int("port", 8080, "listener address")
	retry    = flag.Int("retry", -1, "limit number of reconnection attempts")
	delay    = flag.Int("delay", 30, "time to wait between connection attempts (seconds)>")
	cfg      *config.Config
)

// getSession waits until pki.Document is available and returns a *client.Session
func getSession(cfgFile string) (*client.Session, error) {
	var err error
	cfg, err = config.LoadFile(cfgFile)
	if err != nil {
		return nil, err
	}
	cc, err := client.New(cfg)
	if err != nil {
		return nil, err
	}

	var session *client.Session
	retries := 0
	for session == nil {
		session, err = cc.NewTOFUSession(context.Background())
		switch err {
		case nil:
		case pki.ErrNoDocument:
			_, _, till := epochtime.Now()
			<-time.After(till)
		default:
			<-time.After(time.Duration(*delay) * time.Second)
			if retries == *retry {
				return nil, errors.New("Failed to connect within retry limit")
			}
		}
		retries += 1
	}
	session.WaitForDocument(context.Background())
	return session, nil
}

type kttp struct {
	session *client.Session
	log     *logging.Logger
}

func (k *kttp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d, err := k.session.GetService(*epName)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// serialize the http request
	buf, err := httputil.DumpRequest(r, true)
	// send the http request
	response, err := k.session.BlockingSendUnreliableMessage(d.Name, d.Provider, buf)
	if err != nil {
		// send http error response
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
	return
}

func main() {
	flag.Parse()
	s, err := getSession(*cfgFile)
	if err != nil {
		panic(err)
	}
	// Log to stdout
	logBackend, err := log.New("", *logLevel, false)
	if err != nil {
		panic(err)
	}
	clientLog := logBackend.GetLogger("http_proxy")

	addr := fmt.Sprintf(":%d", *port)
	handler := &kttp{session: s, log: clientLog}
	http.ListenAndServe(addr, handler)
}
