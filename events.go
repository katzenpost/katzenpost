package main

import (
	"time"
)

type KeyExchangeCompleted struct{}

type MessageDelivered struct{}

type MessageReceived struct {
	Message string
}

func handleEvents(events chan interface{}, conversationModel *ConversationModel, contactListModel *ContactListModel) {
	for {
		ev, ok := <-events
		if !ok {
			break
		}
		switch event := ev.(type) {
		case MessageDelivered:
		case MessageReceived:
			var m = NewMessage(nil)
			m.Nickname = accountBridge.Nickname()
			//m.Avatar = accountBridge.Nickname()
			m.Message = event.Message
			m.Timestamp = time.Now()
			conversationModel.AddMessage(m)
		case KeyExchangeCompleted:
		}
	}
}
