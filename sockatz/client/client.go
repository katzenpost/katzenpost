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
	"github.com/katzenpost/katzenpost/client/constants"
	"github.com/katzenpost/katzenpost/client/utils"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/sockatz/common"
	"github.com/katzenpost/katzenpost/sockatz/server"
	"github.com/katzenpost/katzenpost/sockatz/socks5"
	"gopkg.in/op/go-logging.v1"

	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"sync"
	"time"
)

var (
	cfg *config.Config
	// set a minimum floor for the polling loop
	backOffFloor = 100 * time.Millisecond
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
	sync.Mutex

	desc           *utils.ServiceDescriptor
	log            *logging.Logger
	s              *client.Session
	msgToSessionID map[[constants.MessageIDLength]byte][]byte
	payloadLen     int
	receiveOnce    *sync.Once
}

func NewClient(s *client.Session) (*Client, error) {
	l := s.GetLogger("sockatz_client")
	// find a sockatz server descriptor for the request
	desc, err := s.GetService("sockatz")
	if err != nil {
		return nil, err
	}
	return &Client{desc: desc, s: s, log: l, payloadLen: s.SphinxGeometry().UserForwardPayloadLength,
		msgToSessionID: make(map[[constants.MessageIDLength]byte][]byte),
		receiveOnce:    new(sync.Once),
	}, nil
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
		rawResp, err := c.s.BlockingSendUnreliableMessage(c.desc.Name, c.desc.Provider, serialized)
		if err != nil {
			errCh <- err
			return
		}
		p := &server.TopupResponse{}
		err = p.Unmarshal(rawResp)
		if err != nil {
			errCh <- err
			return
		}
		if p.Status != server.TopupSuccess {
			errCh <- errors.New("Topup failure")
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
		rawResp, err := c.s.BlockingSendUnreliableMessage(c.desc.Name, c.desc.Provider, serialized) // blocks until reply arrives
		if err != nil {
			errCh <- err
			return
		}

		p := &server.DialResponse{}
		err = p.Unmarshal(rawResp)
		if err != nil {
			errCh <- err
			return
		}
		if p.Status == server.DialSuccess {
			errCh <- nil
		} else {
			errCh <- errors.New("Dial Failed")
		}
	}()
	return errCh
}

// write incoming packets to QUICProxConn
func (c *Client) handleReply(conn *common.QUICProxyConn, sessionID []byte, errCh chan error, rawResp []byte) {
	c.log.Debugf("Read Response")
	p := &server.ProxyResponse{}
	err := p.Unmarshal(rawResp)
	if err != nil {
		c.log.Errorf("failure to unmarshal server.ProxyResponse: %v", err)
		conn.Close()
		errCh <- err
		return
	}

	// check for ProxyInsufficientFunds or ProxyFailure
	switch p.Status {
	case server.ProxyInsufficientFunds:
		c.log.Debugf("Got ProxyReponse: ProxyInsufficientFunds")

		// XXX: must ensure calls to Topup are synchronous, to avoid double Topup
		err := <-c.Topup(sessionID)
		if err != nil {
			errCh <- err
			return
		}
	case server.ProxySuccess:
		c.log.Debugf("Got ProxyReponse: ProxySuccess: len(%d)", len(p.Payload))
	case server.ProxyFailure:
		c.log.Debugf("Got ProxyReponse: ProxyFailure")
		errCh <- errors.New("ProxyFailure")
		return
	}

	src := common.UniqAddr(sessionID)
	// Write response to to client socket
	if len(p.Payload) != 0 {
		c.log.Debugf("WritePacket to incoming queue from %v", src)
		_, err = conn.WritePacket(context.Background(), p.Payload, src)
		if err != nil {
			if err.Error() == "Halted" {
				c.log.Debugf("WritePacket Halted()")
				return
			}
			// handle unexpected error
			errCh <- err
			return
		}
	}
}
func (c *Client) Proxy(id []byte, conn net.Conn) chan error {
	errCh := make(chan error)

	ctx := context.Background()
	myId := append(id, []byte("client")...)
	k := common.NewQUICProxyConn(myId)

	// start proxy worker that proxies bytes between QUICProxyConn and conn
	c.Go(func() {
		c.log.Debugf("Dialing %v", common.UniqAddr(id))
		proxyConn, err := k.Dial(ctx, common.UniqAddr(id))
		if err != nil {
			errCh <- err
			return
		}

		var wg sync.WaitGroup
		wg.Add(2)

		c.log.Debugf("Starting session %x proxy workers %v <-> %v", id, proxyConn.LocalAddr(), conn.RemoteAddr())
		go func() {
			defer wg.Done()
			_, err := io.Copy(conn, proxyConn)
			if err != nil {
				c.log.Debugf("Proxyworker conn, proxyConn error %v", err)
			}
			c.log.Debugf("Proxyworker conn, proxyConn exiting")
			proxyConn.Close()
			conn.Close()
		}()
		go func() {
			defer wg.Done()
			_, err := io.Copy(proxyConn, conn)
			if err != nil {
				c.log.Debugf("Proxyworker proxyConn, conn error %v", err)
			}
			c.log.Debugf("Proxyworker proxyConn, conn exiting")
			conn.Close()
			proxyConn.Close()
		}()

		c.log.Debugf("Waiting for workers to finish")
		wg.Wait()
		c.log.Debugf("Workers done, closing Conn")
		c.log.Debugf("Workers done, halting transport")
		k.Close()
		k.Halt()
		errCh <- nil
	})

	// start transport worker that receives packets
	c.receiveOnce.Do(func() {
		c.Go(func() {
			c.log.Debugf("Started kaetzchen proxy send worker")
			defer func() {
				c.log.Debugf("Event sink worker terminating gracefully.")
			}()
			for {
				select {
				case e := <-c.s.EventSink:
					switch event := e.(type) {
					case *client.MessageReplyEvent:
						c.Lock()
						sessionID, ok := c.msgToSessionID[*event.MessageID]
						c.Unlock()
						if ok {
							c.handleReply(k, sessionID, errCh, event.Payload)
						}
					default:
						// skip handling event
					}
				case <-k.HaltCh():
					errCh <- nil
					return
				}
			}
		})
	})

	// start transport worker that sends packets
	c.Go(func() {
		c.log.Debugf("Started kaetzchen proxy send worker")
		backOffDelay := 42 * time.Millisecond
		for {
			select {
			case <-k.HaltCh():
				errCh <- nil
				return
			default:
			}
			pkt := make([]byte, c.payloadLen)
			c.log.Debugf("ReadPacket from outbound queue backOff: %v", backOffDelay)
			ctx, cancelFn := context.WithDeadline(context.Background(), time.Now().Add(backOffDelay))

			// do not block waiting for client to send data
			n, destAddr, err := k.ReadPacket(ctx, pkt)
			cancelFn()
			if err != nil {
				if err.Error() == "Halted" {
					c.log.Debugf("Halted in ReadPacket")
					return
				}
				if err != os.ErrDeadlineExceeded {
					// handle unexpected error
					c.log.Error("ReadPacket failure: %v", err)
					errCh <- err
					return
				}
			}
			c.log.Debugf("Read len %d byte packet to send to %v", n, destAddr)

			// wrap packet in a kaetzchen request
			serialized, err := (&server.ProxyCommand{ID: id, Payload: pkt[:n]}).Marshal()
			if err != nil {
				errCh <- err
				return
			}
			serialized, err = (&server.Request{Command: server.Proxy, Payload: serialized}).Marshal()
			// send frame to service and receive a reply
			c.log.Debugf("Send Request{Packet}")

			//XXX: create our own sphinx packet with custom delays
			//c.SendSphinxPacket()
			// don't drop serialized on the floor if SendUnreliableMessage returns "ErrQueueIsFull"
			for {
				msgID, err := c.s.SendUnreliableMessage(c.desc.Name, c.desc.Provider, serialized)
				if err != nil {
					c.log.Errorf("SendUnreliableMessage: %v", err)
					c.log.Errorf("SendUnreliableMessage: backoffDelay %v", backOffDelay)
					backOffDelay += backOffDelay
					// XXX: maxBackoffDelay or select on connection status event
					select {
					case <-time.After(backOffDelay):
					case <-c.HaltCh():
					}
					continue
				} else {
					backOffDelay = (backOffDelay >> 1) + time.Millisecond
					if backOffDelay < backOffFloor {
						backOffDelay = backOffFloor
					}
					c.Lock()
					c.msgToSessionID[*msgID] = id // XXX: must garbage collect ...
					c.Unlock()
					break
				}
			}
		}
		errCh <- nil
	})
	return errCh
}

func (c *Client) SocksHandler(conn net.Conn) {
	defer conn.Close()

	// Read the client's SOCKS handshake.
	req, err := socks5.Handshake(conn)
	if err != nil {
		//log.Errorf("%s - client failed socks handshake: %s", name, err)
		panic(err)
		return
	}

	c.log.Debugf("Got SOCKS5 request: %v", req)

	// Extract the Target address
	var target string

	if req.Conn != nil {
		target = "udp://" + req.Target
	} else {
		target = "tcp://" + req.Target
	}
	tgtURL, err := url.Parse(target)
	if err != nil {
		c.log.Errorf("Failed to parse target: %v", err)
		return
	}

	id := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, id)
	if err != nil {
		panic(err)
	}

	// send a topup command to create a session
	err = <-c.Topup(id)
	if err != nil {
		// XXX: on an error, send Cashu to self or unmark as pending
		// if a malicious service takes the money and runs
		// XXX: debug
		c.log.Errorf("Failed to topup session %v: %v", id, err)
		req.Reply(socks5.ReplyNetworkUnreachable)
		return
	}

	// if the request is a UDPAssociate command, start a local UDP listener
	if req.Command == socks5.UDPAssociateCmd {
		req.Conn = socks5.ListenUDP()
	}

	// dial the target // add to our conneciton map
	err = <-c.Dial(id, tgtURL)

	if err != nil {
		c.log.Errorf("Failed to dial %v", tgtURL)
		return
	}

	// XXX: figure out how far in advance we can return success while completing the above
	// round trips in the background.
	// respond with success
	if err := req.Reply(socks5.ReplySucceeded); err != nil {
		// XXX: debug
		c.log.Errorf("Failed to encdoe response: %v", err)
		return
	}

	// start proxying data
	errCh := c.Proxy(id, conn)
	err = <-errCh
	if err != nil {
		c.log.Errorf("Proxy failed with error: %v", err)
	}
}
