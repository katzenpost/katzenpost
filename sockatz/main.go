package main

import (
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/utils"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/queue"
	"github.com/katzenpost/katzenpost/sockatz/server"
	"github.com/katzenpost/katzenpost/sockatz/socks5"

	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"sync"
	"time"
)

const (
	keySize = 32
)

var (
	salt    = []byte("sockatz_initiator_receiver_secret")
	cfgFile = flag.String("cfg", "sockatz.toml", "config file")
	port    = flag.Int("port", 4242, "listener address")
	cfg     *config.Config
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

type proxyclient struct {
	desc *utils.ServiceDescriptor
	s    *client.Session
}

func main() {
	flag.Parse()
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		panic(err)
	}

	s, err := getSession(*cfgFile)
	c := &proxyclient{s: s}
	if err != nil {
		panic(err)
	}
	if err != nil {
		panic(err)
	}
	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		_ = socksAcceptLoop(c, ln)
		wg.Done()
	}()
	/*
		TODO: Add a HTTP3 CONNECT proxy listener that uses QUIC Datagram to proxy QUIC UDP connections
		wg.Add(1)
		go func() {
			_ = httpAcceptLoop(s, ..
	*/
	// wait until loop has exited
	wg.Wait()
}

func socksAcceptLoop(c *proxyclient, ln net.Listener) error {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				return err
			}
			continue
		}
		go socksHandler(c, conn)
	}
}

func socksHandler(c *proxyclient, conn net.Conn) {
	defer conn.Close()

	// Read the client's SOCKS handshake.
	req, err := socks5.Handshake(conn)
	if err != nil {
		//log.Errorf("%s - client failed socks handshake: %s", name, err)
		panic(err)
		return
	}

	// Extract the Target address
	tgtURL, err := url.Parse(req.Target)
	if err != nil {
		panic(err)
		return
	}

	// find a sockatz server descriptor for the request
	desc, err := c.s.GetService("sockatz")
	if err != nil {
		req.Reply(socks5.ReplyNetworkUnreachable)
		return
	}
	c.desc = desc

	id := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, id)
	if err != nil {
		panic(err)
	}

	// send a topup command to create a session
	err = <-c.topup(id)
	if err != nil {
		// XXX: on an error, send Cashu to self or unmark as pending
		// if a malicious service takes the money and runs
		// XXX: debug
		panic(err)
		req.Reply(socks5.ReplyNetworkUnreachable)
		return
	}

	// if the request is a UDPAssociate command, start a local UDP listener
	if req.Command == socks5.UDPAssociateCmd {
		req.Conn = socks5.ListenUDP()
	}

	// dial the target // add to our conneciton map
	err = <-c.dial(id, tgtURL)

	// XXX: figure out how far in advance we can return success while completing the above
	// round trips in the background.
	// respond with success
	if err := req.Reply(socks5.ReplySucceeded); err != nil {
		// XXX: debug
		panic(err)
	}

	// start proxying data
	c.proxy(id, conn)
}

// topup sends a TopupCommand and returns a channel. err nil means success.
func (c *proxyclient) topup(id []byte) chan error {
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
func (c *proxyclient) dial(id []byte, tgt *url.URL) chan error {
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

func (c *proxyclient) proxy(id []byte, conn net.Conn) {
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

	// read from the local socket, send a proxy command to peer, and write response to local socket
	for {
		// copy from local socket to remote
		f := &server.Frame{Payload: make([]byte, server.PayloadLen)}
		f.Ack = lack
		f.Num = f_write
		conn.SetReadDeadline(time.Now().Add(server.DefaultDeadline))
		n, err := conn.Read(f.Payload)
		// handle short reads
		if errors.Is(err, io.EOF) && n != 0 {
			panic(err)
		} else if errors.Is(err, io.ErrUnexpectedEOF) && n != 0 {
			panic(err)
		} else if errors.Is(err, os.ErrDeadlineExceeded) && n == 0 {
			// skip sending frame
		} else if err != nil {
			// handle unexpected error
			panic(err)
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
			panic(err)
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
				panic(err)
			}

			// check for ErrInsufficientFunds
			if p.Error != nil {
				if errors.Is(p.Error, server.ErrInsufficientFunds) {
					// blocks
					err := <-c.topup(id)
					if err != nil {
						// XXX: debug
						panic(err)
						break
					}
				}
			}
			if p.Frame.Mode != mode {
				panic("wtf")
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
					panic(err)
				} else if errors.Is(err, io.ErrUnexpectedEOF) && n != 0 {
					panic(err)
				} else if errors.Is(err, os.ErrDeadlineExceeded) && n == 0 {
					// skip sending frame
				} else if err != nil {
					// handle unexpected error
					panic(err)
				}
			}
		}
	}
}
