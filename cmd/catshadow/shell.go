// shell.go - shell
// Copyright (C) 2019  David Stainton.
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

package main

import (
	"fmt"
	"strconv"

	"github.com/fatih/color"
	"github.com/katzenpost/catshadow"
	"gopkg.in/abiosoft/ishell.v2"
	"gopkg.in/op/go-logging.v1"
)

// Shell is an interactive terminal shell
// for manipulating our mixnet client.
// It is essentially a terrible user interface. Sorry.
type Shell struct {
	ishell *ishell.Shell
	client *catshadow.Client
	log    *logging.Logger
}

// NewShell creates a new Shell instance.
func NewShell(client *catshadow.Client, log *logging.Logger) *Shell {
	shell := &Shell{
		ishell: ishell.New(),
		client: client,
		log:    log,
	}

	magenta := color.New(color.FgMagenta).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()

	shell.ishell.Println(magenta("catshadow"))
	shell.ishell.SetPrompt(magenta(">>> "))

	shell.ishell.AddCmd(&ishell.Cmd{
		Name: "list_inbox",
		Help: "List inbox.",
		Func: func(c *ishell.Context) {
			// disable the '>>>' for cleaner same line input.
			c.ShowPrompt(false)
			defer c.ShowPrompt(true) // yes, revert after login.
			inbox := shell.client.GetInbox()
			c.Print(fmt.Sprintf("ID\tNickname\n"))
			for id, message := range inbox {
				c.Print(fmt.Sprintf("%d\t%s\n", id, message.Nickname))
			}
			c.Print("\n")
		},
	})

	shell.ishell.AddCmd(&ishell.Cmd{
		Name: "read_inbox",
		Help: "Read inbox.",
		Func: func(c *ishell.Context) {
			// disable the '>>>' for cleaner same line input.
			c.ShowPrompt(false)
			defer c.ShowPrompt(true) // yes, revert after login.
			c.Print(red("message ID: "))
			rawid := c.ReadLine()
			id, err := strconv.Atoi(rawid)
			if err != nil || id < 0 {
				c.Print(fmt.Sprintf("ERROR, invalid message id, must be positive integer\n"))
			} else {
				inbox := shell.client.GetInbox()
				if id > len(inbox) {
					c.Print(fmt.Sprintf("ERROR, requested message id doesn't exist\n"))
				} else {
					mesg := inbox[id]
					c.Print(fmt.Sprintf("%s %s\n%s", mesg.Nickname, mesg.ReceivedTime, mesg.Plaintext))
					c.Print("\n")
				}
			}
		},
	})
	shell.ishell.AddCmd(&ishell.Cmd{
		Name: "delete_contact",
		Help: "Delete a new communications contact",
		Func: func(c *ishell.Context) {
			// disable the '>>>' for cleaner same line input.
			c.ShowPrompt(false)
			defer c.ShowPrompt(true) // yes, revert after login.
			c.Print(red("Contact nickname: "))
			nickname := c.ReadLine()

			shell.client.RemoveContact(nickname)
		},
	})
	shell.ishell.AddCmd(&ishell.Cmd{
		Name: "add_contact",
		Help: "Add a new communications contact",
		Func: func(c *ishell.Context) {
			// disable the '>>>' for cleaner same line input.
			c.ShowPrompt(false)
			defer c.ShowPrompt(true) // yes, revert after login.
			c.Print(red("Contact nickname: "))
			nickname := c.ReadLine()

			c.Print("Enter a shared PANDA passphrase: ")
			passphrase := c.ReadPassword()
			shell.client.NewContact(nickname, []byte(passphrase))
		},
	})
	shell.ishell.AddCmd(&ishell.Cmd{
		Name: "list_contacts",
		Help: "List contacts.",
		Func: func(c *ishell.Context) {
			// disable the '>>>' for cleaner same line input.
			c.ShowPrompt(false)
			defer c.ShowPrompt(true) // yes, revert after login.
			nicknames := shell.client.GetNicknames()
			c.Print(fmt.Sprintf("Nickname\n"))
			for _, name := range nicknames {
				c.Print(fmt.Sprintf("%s\n", name))
			}
			c.Print("\n")
		},
	})
	shell.ishell.AddCmd(&ishell.Cmd{
		Name: "send_message",
		Help: "Send a message.",
		Func: func(c *ishell.Context) {
			// disable the '>>>' for cleaner same line input.
			c.ShowPrompt(false)
			defer c.ShowPrompt(true) // yes, revert after login.
			c.Print(red("Contact nickname: "))
			nickname := c.ReadLine()

			c.Print("Message: (ctrl-D to end)\n")
			message := c.ReadMultiLines("\n.\n")
			shell.client.SendMessage(nickname, []byte(message))
		},
	})
	shell.ishell.AddCmd(&ishell.Cmd{
		Name: "halt",
		Help: "Stop the client",
		Func: func(c *ishell.Context) {
			// disable the '>>>' for cleaner same line input.
			c.ShowPrompt(false)
			defer c.ShowPrompt(true) // yes, revert after login.
			c.Print(green("User requested shutdown.\n"))

			shell.Halt()
		},
	})

	halt := func(context *ishell.Context) {
		shell.Halt()
	}
	shell.ishell.EOF(halt)

	return shell
}

// Run runs the Shell.
func (s *Shell) Run() {
	// Let ishell do signal handling.
	s.ishell.Interrupt(func(c *ishell.Context, count int, input string) {
		s.Halt()
	})
	s.ishell.Run()
}

// Halt halts the Shell.
func (s *Shell) Halt() {
	s.client.Shutdown()
	s.ishell.Close()
}
