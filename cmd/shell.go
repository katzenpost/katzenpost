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
	"github.com/fatih/color"
	"github.com/katzenpost/catshadow"
	"gopkg.in/abiosoft/ishell.v2"
	"gopkg.in/op/go-logging.v1"
)

type Shell struct {
	ishell *ishell.Shell
	client *catshadow.Client
	log    *logging.Logger
}

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
		Name: "read_inbox",
		Help: "Read inbox.",
		Func: func(c *ishell.Context) {
			// disable the '>>>' for cleaner same line input.
			c.ShowPrompt(false)
			defer c.ShowPrompt(true) // yes, revert after login.
			c.Print(red("Contact nickname: "))
			nickname := c.ReadLine()

			message := shell.client.MessageFrom(nickname)
			if len(message) > 0 {
				c.Print(string(message))
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

	return shell
}

func (s *Shell) Run() {
	// Let ishell do signal handling.
	s.ishell.Interrupt(func(c *ishell.Context, count int, input string) {
		s.Halt()
	})
	s.ishell.Run()
}

func (s *Shell) Halt() {
	s.client.Shutdown()
	s.ishell.Close()
}
