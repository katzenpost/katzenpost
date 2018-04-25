// proxy.go - Katzenpost client mail proxy upstream proxy support.
// Copyright (C) 2018  Yawning Angel.
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

// Package proxy implements the support for an upstream (outgoing) proxy.
package proxy

import (
	"context"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/katzenpost/core/utils"
	"golang.org/x/net/proxy"
)

const (
	typeNone      = "none"
	typeTorSocks5 = "tor+socks5"
	typeSocks5    = "socks5"

	netUnix = "unix"
	netTCP  = "tcp"

	maxSocks5AuthLen = 255
)

var torSocks5ProcessIsolation string

// Config is the proxy configuration.
type Config struct {
	// Type is the proxy type (Eg: "none"," socks5", "tor+socks5").
	Type string

	// Network is the proxy address' network (`unix`, `tcp`).
	Network string

	// Address is the proxy's address.
	Address string

	// User is the optional proxy username.
	User string

	// Password is the optional proxy password.
	Password string

	auth *proxy.Auth
}

// DialContextFn is a function that matches the Dialer.DialContext prototype.
type DialContextFn func(context.Context, string, string) (net.Conn, error)

// FixupAndValidate applies defaults to config entires and validates the
// supplied configuration.
func (cfg *Config) FixupAndValidate() error {
	cfg.Type = strings.ToLower(cfg.Type)
	switch cfg.Type {
	case "":
		cfg.Type = typeNone
	case typeNone:
	case typeSocks5, typeTorSocks5:
		uLen, pLen := len(cfg.User), len(cfg.Password)
		if uLen > maxSocks5AuthLen {
			return fmt.Errorf("proxy/config: User too long")
		}
		if pLen > maxSocks5AuthLen {
			return fmt.Errorf("proxy/config: Password too long")
		}
		if uLen != 0 && pLen == 0 || uLen == 0 && pLen != 0 {
			return fmt.Errorf("proxy/config: Both User and Password must be specified")
		}
		if uLen != 0 && pLen != 0 {
			if cfg.Type == typeTorSocks5 {
				return fmt.Errorf("proxy:config: Tor SOCKS5 conflicts with setting User/Password")
			}
			cfg.auth = &proxy.Auth{
				User:     cfg.User,
				Password: cfg.Password,
			}
		}

		cfg.Network = strings.ToLower(cfg.Network)
		switch cfg.Network {
		case netTCP:
			if err := utils.EnsureAddrIPPort(cfg.Address); err != nil {
				return fmt.Errorf("proxy/config: Address '%v' is invalid: %v", cfg.Address, err)
			}
		case netUnix:
			fi, err := os.Lstat(cfg.Address)
			if err != nil {
				return fmt.Errorf("proxy/config: Address '%v' failed to stat(): %v", cfg.Address, err)
			}
			if fi.Mode()&os.ModeSocket == 0 {
				return fmt.Errorf("proxy/config: Address '%v' does not appear to be a socket", cfg.Address)
			}
		default:
			return fmt.Errorf("proxy/config: Network '%v' is invalid", cfg.Network)
		}
	default:
		return fmt.Errorf("proxy/config: Type '%v' is invalid", cfg.Type)
	}
	return nil
}

// ToDialContext returns a function matching Dialer.DialContext() that will
// utilize the configured proxy or nil iff no proxy is configured.
func (cfg *Config) ToDialContext(tag string) DialContextFn {
	switch cfg.Type {
	case typeNone:
		return nil
	case typeSocks5, typeTorSocks5:
		return cfg.newContextSOCKS5(tag)
	default:
		panic("proxy: ToDialContext(): invalid type: " + cfg.Type)
	}
}

func (cfg *Config) newContextSOCKS5(tag string) DialContextFn {
	auth := cfg.auth
	if cfg.Type == typeTorSocks5 {
		auth = &proxy.Auth{}

		// Craft an SOCKSPort isolation entry from `tag`, and jam it into
		// the User/Password.
		sum := sha512.Sum512_256([]byte(tag))
		isolationTag := torSocks5ProcessIsolation + hex.EncodeToString(sum[:16])
		auth.User = isolationTag
		auth.Password = string([]byte{0x00})
	}

	s := &contextSOCKS5{
		proxyNet:  cfg.Network,
		proxyAddr: cfg.Address,
		proxyAuth: auth,
	}
	return s.dialContext
}

type contextSOCKS5 struct {
	proxyNet  string
	proxyAddr string
	proxyAuth *proxy.Auth
}

func (s *contextSOCKS5) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// One day, golang.org/x/net/proxy will support using a context.
	// See: https://github.com/golang/go/issues/19354
	fwdDialer := &contextDialer{
		ctx:    ctx,
		connCh: make(chan net.Conn),
	}
	defer close(fwdDialer.connCh)

	socksDialer, err := proxy.SOCKS5(s.proxyNet, s.proxyAddr, s.proxyAuth, fwdDialer)
	if err != nil {
		return nil, err
	}
	go func() {
		// Wait for the forward dial process to finish.
		conn, ok := <-fwdDialer.connCh
		if !ok {
			return
		}

		// Do the "right" thing based on the context.
		select {
		case <-ctx.Done():
			if conn != nil {
				conn.Close()
			}
		case <-fwdDialer.connCh:
		}
	}()

	return socksDialer.Dial(network, address)
}

type contextDialer struct {
	ctx    context.Context // I know this is frowned upon.
	connCh chan net.Conn
}

func (c *contextDialer) Dial(network, address string) (net.Conn, error) {
	directDialer := &net.Dialer{}
	conn, err := directDialer.DialContext(c.ctx, network, address)
	c.connCh <- conn
	return conn, err
}

func init() {
	// Initialize the per-process Tor SOCKS isolation tag.  This is
	// probably massive overkill.
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[0:], uint64(os.Getpid()))
	binary.BigEndian.PutUint64(buf[8:], uint64(time.Now().Unix()))
	sum := sha512.Sum512_256(buf[:])
	torSocks5ProcessIsolation = "katzenpost/mailproxy:" + hex.EncodeToString(sum[:8]) + ":"
}
