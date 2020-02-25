package main

import (
	"sort"
	"time"

	"github.com/katzenpost/catshadow"
)

// loadContactList loads the contact list for an account
func loadContactList(contactListModel *ContactListModel, nickNames []string) {
	for _, nickName := range nickNames {
		var contact = NewContact(nil)
		contact.Nickname = nickName
		// XXX contact.Avatar = "https://picsum.photos/128/128"
		contactListModel.AddContact(contact)
	}
}

// loadConversation loads the conversation with a contact
func loadConversation(client *catshadow.Client, contact string) {
	accountBridge.SetRecipient(contact)

	conversationModel.Clear()
	conversation := client.GetConversation(contact)

	var msgs Messages
	for _, message := range conversation {
		var m = NewMessage(nil)

		if message.Outbound {
			m.Nickname = accountBridge.Nickname()
		} else {
			m.Nickname = contact
		}

		m.Avatar = ""
		m.Message = string(message.Plaintext)
		m.Timestamp = message.Timestamp
		m.Outbound = message.Outbound

		msgs = append(msgs, m)
	}

	sort.Sort(msgs)

	for _, m := range msgs {
		conversationModel.AddMessage(m)
	}
}

// addContact adds a contact to the contact list
func addContact(client *catshadow.Client, nickname string, passphrase string) bool {
	client.NewContact(nickname, []byte(passphrase))

	var c = NewContact(nil)
	c.Nickname = nickname
	c.Avatar = ""
	contactListModel.AddContact(c)

	return true
}

// sendMessage sends a message to a contact
func sendMessage(client *catshadow.Client, nickname string, message string) {
	id := client.SendMessage(nickname, []byte(message))

	var m = NewMessage(nil)
	m.MessageID = string(id[:])
	m.Nickname = accountBridge.Nickname()
	m.Avatar = accountBridge.Nickname()
	m.Message = message
	m.Timestamp = time.Now()
	m.Outbound = true
	conversationModel.AddMessage(m)
}
