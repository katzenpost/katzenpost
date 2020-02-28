package main

import (
	"fmt"

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
			status := "Connecting..."
			if event.IsConnected {
				status = "Connected"
			}
			if event.Err != nil {
				status = "Disconnected"
				accountBridge.SetError(event.Err.Error())
			}

			accountBridge.SetStatus(status)

		case *catshadow.KeyExchangeCompletedEvent:
			// XXX fix me

		case *catshadow.MessageSentEvent:
			conversationModel.updateMessageStatus(string(event.MessageID[:]), StatusSent)

		case *catshadow.MessageDeliveredEvent:
			conversationModel.updateMessageStatus(string(event.MessageID[:]), StatusDelivered)

		case *catshadow.MessageReceivedEvent:
			var m = NewMessage(nil)
			m.Nickname = event.Nickname
			m.Avatar = "" // XXX fix me
			m.Message = string(event.Message)
			m.Timestamp = event.Timestamp
			conversationModel.AddMessage(m)

			notify("catchat", "New message received from "+m.Nickname)

		default:
			// This case indicates a programming BUG!
			panic(fmt.Sprintf("%s is an unknown event received, aborting", event))
		}
	}
}
