// server_test.go - Noise based wire protocol server tests.
// Copyright (C) 2017  David Anthony Stainton
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

package server

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type EchoSession struct{}

func (e EchoSession) Initiate(conn io.ReadWriteCloser) error {
	if _, err := io.Copy(conn, conn); err != nil {
		fmt.Println(err.Error())
		return err
	}
	return nil
}

func (e EchoSession) Close() error {
	return nil
}

func (e EchoSession) Send(payload []byte) error {
	return nil
}

func TestServer(t *testing.T) {
	assert := assert.New(t)

	network := "tcp"
	address := "127.0.0.1:33692"
	echoSession := EchoSession{}
	l := New(network, address, echoSession.Initiate, nil)
	defer l.Stop()
	go func() {
		err := l.Start()
		if err != nil {
			panic(err)
		}
	}()

	time.Sleep(time.Second)

	// In this test, we start 10 clients, each making a single connection
	// to the server. Then each will write 10 messages to the server, and
	// read the same 10 messages back. After that the client quits.
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() {
				fmt.Printf("Quiting client #%d", id)
			}()

			conn, err := net.Dial(network, address)
			if err != nil {
				fmt.Println(err.Error())
				return
			}
			defer func() {
				err := conn.Close()
				if err != nil {
					panic(err)
				}
			}()

			for j := 0; j < 10; j++ {
				message := fmt.Sprintf("client #%d, count %d\r\n", id, j)
				fmt.Fprint(conn, message)
				result, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					fmt.Println(err.Error())
					return
				}
				fmt.Printf("Received: %s", result)
				assert.Equal(message, result, "expected echo string to equal sent string")
				time.Sleep(100 * time.Millisecond)
			}
		}(i)
	}

	// We sleep for a couple of seconds, let the clients run their jobs,
	// then we exit, which triggers the defer function that will shutdown
	// the server.
	time.Sleep(4 * time.Second)
}
