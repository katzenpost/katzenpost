// plugins.go - katzenpost client plugins "manager"
// Copyright (C) 2021  David Stainton.
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

// Package cborplugin is a plugin system allowing mix network services
// to be added in any language. It communicates queries and responses to and from
// the mix server using CBOR over HTTP over UNIX domain socket. Beyond that,
// a client supplied SURB is used to route the response back to the client
// as described in our Kaetzchen specification document:
//
// https://github.com/katzenpost/docs/blob/master/specs/kaetzchen.rst
//
package cborplugin

import (
	"fmt"
	"sync"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/client/config"
	"github.com/katzenpost/client/constants"
	"github.com/katzenpost/client/events"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/worker"
)

type SentMessage struct {
	Time   time.Time
	Client *Client
}

type Plugins struct {
	worker.Worker

	log         *logging.Logger
	clients     []*Client
	eventsInCh  chan events.Event
	replyRoutes *sync.Map // message ID -> *SentMessage
}

func NewPlugins(session Session, logBackend *log.Backend, pluginConfigs []*config.CBORPlugin) *Plugins {
	p := &Plugins{
		clients:     make([]*Client, 0),
		eventsInCh:  make(chan events.Event),
		replyRoutes: new(sync.Map),
	}

	for _, pluginConf := range pluginConfigs {
		args := []string{}
		if len(pluginConf.Config) > 0 {
			for key, val := range pluginConf.Config {
				args = append(args, fmt.Sprintf("-%s", key), val.(string))
			}
		}
		plugin := New(p, session, logBackend)
		err := plugin.Start(pluginConf.Command, args)
		if err != nil {
			p.log.Fatal(err)
		}
	}

	p.Go(p.worker)
	return p
}

func (p *Plugins) EventSink() chan events.Event {
	return p.eventsInCh
}

func (p *Plugins) worker() {
	for {
		select {
		case <-p.HaltCh():
			return
		case event := <-p.eventsInCh:
			p.processEvent(event)
		}
	}
}

func (p *Plugins) processEvent(event events.Event) {
	switch v := event.(type) {
	case *events.ConnectionStatusEvent:
	case *events.MessageReplyEvent:
		rawPlugin, ok := p.replyRoutes.Load(v.MessageID)
		if !ok {
			p.log.Error("no reply route found for message ID")
			return
		}
		plugin, ok := rawPlugin.(*Client)
		if !ok {
			p.log.Error("invalid plugin found")
			return
		}
		plugin.WriteChan() <- &Event{
			MessageReplyEvent: v,
		}
		p.replyRoutes.Delete(v.MessageID)
	case *events.MessageSentEvent:
	case *events.MessageIDGarbageCollected:
	case *events.NewDocumentEvent:
	default:
		p.log.Error("Plugins: received invalid event type")
		return
	}
}

func (p *Plugins) ReplyToSentMessage(id *[constants.MessageIDLength]byte, client *Client) {
	sentMessage := SentMessage{
		Time:   time.Now(),
		Client: client,
	}
	p.replyRoutes.Store(id, &sentMessage)
}
