package main

import (
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/sockatz/client"
	"github.com/katzenpost/katzenpost/sockatz/socks5"

	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
)

const (
	keySize = 32
)

var (
	salt    = []byte("sockatz_initiator_receiver_secret")
	cfgFile = flag.String("cfg", "sockatz.toml", "config file")
	port    = flag.Int("port", 4242, "listener address")
)

// getSession waits until pki.Document is available and returns a *client.Session
func main() {
	flag.Parse()
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		panic(err)
	}

	s, err := client.GetSession(*cfgFile)
	if err != nil {
		panic(err)
	}

	c, err := client.NewClient(s)
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

func socksAcceptLoop(c *client.Client, ln net.Listener) error {
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

func socksHandler(c *client.Client, conn net.Conn) {
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
		panic(err)
		req.Reply(socks5.ReplyNetworkUnreachable)
		return
	}

	// if the request is a UDPAssociate command, start a local UDP listener
	if req.Command == socks5.UDPAssociateCmd {
		req.Conn = socks5.ListenUDP()
	}

	// dial the target // add to our conneciton map
	err = <-c.Dial(id, tgtURL)

	// XXX: figure out how far in advance we can return success while completing the above
	// round trips in the background.
	// respond with success
	if err := req.Reply(socks5.ReplySucceeded); err != nil {
		// XXX: debug
		panic(err)
	}

	// start proxying data
	c.Proxy(id, conn)
}
