package main

import (
	"github.com/katzenpost/katzenpost/katzensocks/client"

	"flag"
	"fmt"
	"net"
	"sync"
)

var (
	cfgFile = flag.String("cfg", "katzensocks.toml", "config file")
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
		go c.SocksHandler(conn)
	}
}
