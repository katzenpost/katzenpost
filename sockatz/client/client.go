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
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/utils"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/queue"
	"github.com/katzenpost/katzenpost/sockatz/server"

	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"time"
)

var (
	cfg *config.Config
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
	desc *utils.ServiceDescriptor
	s    *client.Session
}

func NewClient(s *client.Session) (*Client, error) {
	// find a sockatz server descriptor for the request
	desc, err := s.GetService("sockatz")
	if err != nil {
		return nil, err
	}
	return &Client{desc: desc, s: s}, nil
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
	defer close(errCh)
	frames := make(map[uint64]*server.Frame)
	f_read := uint64(1)
	f_write := uint64(1) // ack 0 must be a special case of nothing yet received, so frames start # from 1
	pack := uint64(0)    // ack received from peer
	lack := uint64(0)    // our greatest sequential ack'd frame
	rwin := uint64(0)

	// each socket read is synchronous - a client must request the
	// data to read it - each frame sent in the forward direction
	// opportunistically includes data from the client to the
	// server

	ReorderBuffer := queue.New()

	var mode server.Mode
	switch conn.(type) {
	case *net.UDPConn:
		mode = server.UDP
	case *net.TCPConn:
		mode = server.TCP
	}

	go func() {
		// read from the local socket, send a proxy command to peer, and write response to local socket
		for {
			// copy from local socket to remote
			f := &server.Frame{Payload: make([]byte, server.PayloadLen), Ack: lack, Num: f_write}
			conn.SetReadDeadline(time.Now().Add(server.DefaultDeadline))
			n, err := conn.Read(f.Payload)
			// handle short reads
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

			// store frame for (re)transmission
			frames[f.Num] = f

			// XXX: tune retransmit
			if f.Num > pack+rwin && pack != 0 {
				// resend pack + 1
				if f2, ok := frames[pack+1]; ok {
					f = f2
				}
			}

			serialized, err := (&server.ProxyCommand{ID: id, Frame: f}).Marshal()
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
				if p.Frame.Mode != mode {
					errCh <- server.ErrInvalidFrame
					return
				}

				// increment written frame pointer
				f_write += 1

				// ignore previously seen frames
				if p.Frame.Num < f_read {
					break
				}

				// delete acknowleged frames
				if p.Frame.Ack > pack {
					for i := pack; i <= p.Frame.Ack; i++ {
						delete(frames, i)
					}
					pack = p.Frame.Ack
				}

				// A frame received out of order is placed into a re-order buffer
				doWrite := false
				switch {
				case p.Frame.Num < f_read:
				case p.Frame.Num > f_read:
					// XXX: verify that duplicate priority Enqueue is OK.
					ReorderBuffer.Enqueue(f.Num, f)
					head := ReorderBuffer.Peek().Value.(*server.Frame)
					if head != nil && head.Num == f_read {
						ReorderBuffer.Pop()
						// f points at the next sequential frame
						f = head
						doWrite = true
					}
				case p.Frame.Num == f_read:
					doWrite = true
				}
				if doWrite {
					f_read += 1
					n, err := conn.Write(f.Payload)
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
		}
		errCh <- nil
	}()
	return errCh
}
