package main

import (
	"context"
	"encoding/base64"
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/sockatz/socks5"
	"github.com/katzenpost/katzenpost/stream"

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
		session, err = cc.NewTOFUSession()
		switch err {
		case nil:
		case pki.ErrNoDocument:
			_, _, till := epochtime.Now()
			<-time.After(till)
		default:
			return nil, err
		}
	}
	session.WaitForDocument()
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

	// create a StreamSocketRequest for the resource and specifiy the secret
	// XXX: StreamSecret should be encrypted to the service's epoch key
	// FIXME: the pki parameters should be used to obtain the epoch key for the session
	// so that a zero round trip handshake can be used to encrypt the stream session details
	// wth a a session key that rotates each epoch which clients will encrypt their requests to
	u, err := url.Parse(socksReq.Target)
	if err != nil {
		panic(err)
		return
	}
	// XXX: actually send this to the remote service
	local, err:= stream.NewDuplex(session)
	if err != nil {
		panic(err)
	}
	ssr := StreamSocketRequest{Endpoint: u, Address: local.RemoteAddr()}
	go func() {
		fmt.Println("launching socks5<->stream<->gateway proxy request")
		// connect to the stream of the requesting client
		s, err := stream.DialDuplex(session, "", ssr.Address.String())
		if err != nil {
			panic(err)
		}
		// dial the remote host (using our local proxy config if specified)
		pCfg := cfg.UpstreamProxyConfig()
		pCfg.Network = "tcp"
		pCfg.Type = "socks5"
		pCfg.Address= "10.42.42.42:9050"

		var con net.Conn
		ctx := context.Background()
		dialer := pCfg.ToDialContext("")
		if dialer == nil {
			con, err = net.Dial("tcp", ssr.Endpoint.String())
			if err != nil {
				panic(err)
			}
		} else{
			con, err = dialer(ctx, "tcp", ssr.Endpoint.String())
			if err != nil {
				panic(err)
			}
		}
		err = socksReq.Reply(socks5.ReplySucceeded)
		if err != nil {
			panic(err)
		}
		defer s.Close()
		defer con.Close()

		if err = copyLoop(s, con); err != nil {
			fmt.Println("connection lost with err", err)
		}
		fmt.Println("connection closed")
	}()

	// send request to the upstream socket server and await the response
	if err = copyLoop(conn, local); err != nil {
	}
	// log done
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

func newSecret() []byte {
	// generate secrets
	newsecret := &[keySize]byte{}
	io.ReadFull(rand.Reader, newsecret[:])
	secret := base64.StdEncoding.EncodeToString(newsecret[:])
	return []byte(secret)
}

type StreamSocketRequest struct {
	Endpoint *url.URL
	Address  *stream.StreamAddr
}
