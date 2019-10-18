package main

import (
	"fmt"
	"time"

	"github.com/katzenpost/catshadow"
	"github.com/katzenpost/client"
)

func handleEvents(events <-chan interface{}, conversationModel *ConversationModel, contactListModel *ContactListModel) {
	for {
		ev, ok := <-events
		if !ok {
			return
		}
		switch event := ev.(type) {
		case *client.ConnectionStatusEvent:
			// XXX fix me
		case *catshadow.KeyExchangeCompletedEvent:
			// XXX fix me
		case *catshadow.MessageSentEvent:
			// XXX fix me
		case *catshadow.MessageDeliveredEvent:
			// XXX fix me
		case *catshadow.MessageReceivedEvent:
			var m = NewMessage(nil)
			m.Nickname = event.Nickname
			m.Avatar = "" // XXX fix me
			m.Message = string(event.Message)
			m.Timestamp = time.Now()
			conversationModel.AddMessage(m)
		default:
			// This case indicates a programming BUG!
			panic(fmt.Sprintf("%s is an unknown event received, aborting", event))
		}
	}
}
