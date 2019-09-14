package main

import (
	"time"

	"github.com/katzenpost/catshadow"
)

func handleEvents(events <-chan interface{}, conversationModel *ConversationModel, contactListModel *ContactListModel) {
	for {
		ev, ok := <-events
		if !ok {
			break
		}
		switch event := ev.(type) {
		case catshadow.MessageDelivered:
		case catshadow.MessageReceived:
			var m = NewMessage(nil)
			m.Nickname = accountBridge.Nickname()
			// XXX fix me: m.Avatar = accountBridge.Nickname()
			m.Message = string(event.Message)
			m.Timestamp = time.Now()
			conversationModel.AddMessage(m)
		case catshadow.KeyExchangeCompleted:
		}
	}
}
