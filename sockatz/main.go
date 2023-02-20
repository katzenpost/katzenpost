package main

import (
	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/sockatz/server"
	"github.com/katzenpost/katzenpost/sockatz/socks5"
	"github.com/katzenpost/katzenpost/stream"

	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
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

func main() {
	flag.Parse()
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		panic(err)
	}

	s, err := getSession(*cfgFile)
	if err != nil {
		panic(err)
	}
	if err != nil {
		panic(err)
	}
	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		_ = clientAcceptLoop(s, ln)
		wg.Done()
	}()
	// wait until loop has exited
	wg.Wait()
}

func clientAcceptLoop(session *client.Session, ln net.Listener) error {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				return err
			}
			continue
		}
		go clientHandler(session, conn)
	}
}

func clientHandler(session *client.Session, conn net.Conn) {
	defer conn.Close()

	// Read the client's SOCKS handshake.
	socksReq, err := socks5.Handshake(conn)
	if err != nil {
		//log.Errorf("%s - client failed socks handshake: %s", name, err)
		panic(err)
		return
	}

	// create a SockatzRequest for the resource and specifiy the secret
	// XXX: Stream secret MUST BE ENCRYPTED using a PQ handshake or Stream is not PQ

	// FIXME: the plugin should generate a (ctidh) keypair each epoch and publish it
	// using the pki parameters so that clients

	// clients will then construct a zero round trip handshake that encrypts the requested
	// endpoint and stream secret
	u, err := url.Parse(socksReq.Target)
	if err != nil {
		panic(err)
		return
	}
	local, err := stream.NewDuplex(session)
	if err != nil {
		panic(err)
	}
	defer local.Close()

	ssr := server.SockatzRequest{Endpoint: u, Stream: local.RemoteAddr().String()}

	// find a sockatz server for the request
	d, err := session.GetService("sockatz")
	if err != nil {
		socksReq.Reply(socks5.ReplyNetworkUnreachable)
		return
	}

	serialized, err := cbor.Marshal(ssr)
	if err != nil {
		// XXX: log client err
		socksReq.Reply(socks5.ReplyGeneralFailure)
		return
	}
	_, err = session.BlockingSendUnreliableMessage(d.Name, d.Provider, serialized)
	if err != nil {
		socksReq.Reply(socks5.ReplyGeneralFailure)
		return
	}
	socksReq.Reply(socks5.ReplySucceeded)
	if err != nil {
		return
	}

	fmt.Println("starting copyLoop")

	// send request to the upstream socket server and await the response
	if err = copyLoop(conn, local); err != nil {
		fmt.Println("copyLoop err", err)
		// log err
	} else {
		fmt.Println("copyLoop done")
	}
}

func copyLoop(a io.ReadWriteCloser, b io.ReadWriteCloser) error {
	// Note: b is always the Stream.  a is the SOCKS/ORPort connection.
	errChan := make(chan error, 2)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, err := io.Copy(b, a)
		if err != nil {
			errChan <- err
		}
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(a, b)
		if err != nil {
			errChan <- err
		}
	}()

	// Wait for both upstream and downstream to close.  Since one side
	// terminating closes the other, the second error in the channel will be
	// something like EINVAL (though io.Copy() will swallow EOF), so only the
	// first error is returned.
	wg.Wait()
	if len(errChan) > 0 {
		return <-errChan
	}

	return nil
}
