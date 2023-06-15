// client.go - stream socket client using cbor plugin system
// Copyright (C) 2023  Masala
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

package client

import (
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/core/log"
	"gopkg.in/op/go-logging.v1"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/utils"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/sockatz/common"
	"github.com/katzenpost/katzenpost/sockatz/server"

	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"time"
	"sync"
)

var (
	cfg        *config.Config
	payloadLen = 1200
)

func GetSession(cfgFile string) (*client.Session, error) {
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
	for session == nil {
		session, err = cc.NewTOFUSession(context.Background())
		switch err {
		case nil:
		case pki.ErrNoDocument:
			_, _, till := epochtime.Now()
			<-time.After(till)
		default:
			return nil, err
		}
	}
	session.WaitForDocument(context.Background())
	return session, nil
}

type Client struct {
	worker.Worker

	desc *utils.ServiceDescriptor
	log *logging.Logger
	s    *client.Session
}

func NewClient(s *client.Session) (*Client, error) {
	logBackend, err := log.New("", "DEBUG", false)
	if err != nil {
		panic(err)
	}
	l := logBackend.GetLogger("sockatz_server")

	// find a sockatz server descriptor for the request
	desc, err := s.GetService("sockatz")
	if err != nil {
		return nil, err
	}
	return &Client{desc: desc, s: s, log: l}, nil
}

// topup sends a TopupCommand and returns a channel. err nil means success.
func (c *Client) Topup(id []byte) chan error {
	errCh := make(chan error)
	go func() {
		defer close(errCh)
		// XXX: Get Cashu from wallet API
		nuts := make([]byte, 512)
		_, err := io.ReadFull(rand.Reader, nuts)
		if err != nil {
			errCh <- err
			return
		}

		// Send a TopupCommand to create a proxy session on the server
		serialized, err := (&server.TopupCommand{ID: id, Nuts: nuts}).Marshal()
		if err != nil {
			errCh <- err
			return
		}

		// Wrap in a Request
		serialized, err = (&server.Request{Command: server.Topup, Payload: serialized}).Marshal()
		if err != nil {
			errCh <- err
			return
		}

		// blocks until reply arrives
		resp, err := c.s.BlockingSendUnreliableMessage(c.desc.Name, c.desc.Provider, serialized)
		if err == nil {
			p := server.TopupResponse{}
			err := p.Unmarshal(resp)
			if err != nil {
				errCh <- err
				return
			}
		} else {
			errCh <- err
			return
		}
		errCh <- nil // NoError
	}()
	return errCh
}

// dial sends a DialCommand and returns a channel. err nil means success.
func (c *Client) Dial(id []byte, tgt *url.URL) chan error {
	errCh := make(chan error)
	go func() {
		defer close(errCh)
		serialized, err := (&server.DialCommand{ID: id, Target: tgt}).Marshal()
		if err != nil {
			panic(err)
		}
		serialized, err = (&server.Request{Command: server.Dial, Payload: serialized}).Marshal()
		// send frame to service and receive a reply
		// XXX: do not use blocking client because it serializes all the request/response pairs
		// so there is no interleaving, which adds a lot of delay..
		// implement a lower level client using minclient and do not use these blocking methods.
		resp, err := c.s.BlockingSendUnreliableMessage(c.desc.Name, c.desc.Provider, serialized) // blocks until reply arrives
		if err == nil {
			p := server.DialResponse{}
			err := p.Unmarshal(resp)
			if err == nil {
				if p.Error == nil {
					// XXX: does not support opportunistic payload yet
					errCh <- nil
				} else {
					errCh <- err
				}
			} else {
				errCh <- err
			}
		} else {
			errCh <- err
		}
	}()
	return errCh
}

func (c *Client) Proxy(id []byte, conn net.Conn) chan error {
	errCh := make(chan error)

	ctx := context.Background()
	k := common.NewKatConn(c.log)

	// start proxy worker that proxies bytes between KatConn and conn
	
	c.Go(func() {
		proxyConn, err := k.Dial(ctx)
		if err != nil {
			errCh <- err
			return
		}
	
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			_, err := io.Copy(conn, proxyConn)
			if err != nil {
				errCh <- err
			}
		}()
		go func() {
			defer wg.Done()
			_, err := io.Copy(proxyConn, conn)
			if err != nil {
				errCh<- err
			}
		}()
		wg.Wait()
		close(errCh)
	})


	// start transport worker that reads frames to/from katzenpost and KatConn
	c.Go(func() {
		for {
			select {
			case <-c.HaltCh():
				return
			default:
			}
			// copy from local socket to remote
			k.SetReadDeadline(time.Now().Add(server.DefaultDeadline))
			pkt := make([]byte, payloadLen)
			n, err := k.ReadPacket(pkt)
			// handle short reads
			if errors.Is(err, io.EOF) && n != 0 {
				errCh <- err
				return
			} else if errors.Is(err, io.ErrUnexpectedEOF) && n != 0 {
				errCh <- err
				return
			} else if errors.Is(err, os.ErrDeadlineExceeded) {
				// send empty or partial forward payload
			} else if err != nil {
				// handle unexpected error
				errCh <- err
				return
			}

			// wrap packet in a kaetzchen request
			serialized, err := (&server.ProxyCommand{ID: id, Payload: pkt}).Marshal()
			if err != nil {
				errCh <- err
				return
			}
			serialized, err = (&server.Request{Command: server.Proxy, Payload: serialized}).Marshal()
			// send frame to service and receive a reply
			// XXX: do not use blocking client because it serializes all the request/response pairs
			// so there is no interleaving, which adds a lot of delay..
			// implement a lower level client using minclient and do not use these blocking methods.
			resp, err := c.s.BlockingSendUnreliableMessage(c.desc.Name, c.desc.Provider, serialized) // blocks until reply arrives
			if err == nil {
				p := server.ProxyResponse{}
				err := p.Unmarshal(resp)
				if err != nil {
					// XXX handle unmarshal err
					errCh <- err
					return
				}

				// check for ErrInsufficientFunds
				if p.Error != nil {
					if errors.Is(p.Error, server.ErrInsufficientFunds) {
						// blocks
						err := <-c.Topup(id)
						if err != nil {
							// XXX: debug
							errCh <- err
							return
						}
					}
				}

				// Write response to to client socket
				n, err := k.WritePacket(p.Payload)
				// handle short writes
				if errors.Is(err, io.EOF) && n != 0 {
					errCh <- err
					return
				} else if errors.Is(err, io.ErrUnexpectedEOF) && n != 0 {
					errCh <- err
					return
				} else if errors.Is(err, os.ErrDeadlineExceeded) && n == 0 {
					// skip sending frame
				} else if err != nil {
					// handle unexpected error
					errCh <- err
					return
				}
			}
		}
		errCh <- nil
	})
	return errCh
}
