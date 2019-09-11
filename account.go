package main

import (
	"time"

	"github.com/katzenpost/catshadow"
)

var (
	conversations = make(map[string][]*Message)
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
	conversationModel.Clear()
	accountBridge.SetRecipient(contact)
	conversation := client.GetConversation(contact)
	for _, message := range conversation {
		msg := &Message{
			Nickname:  contact,
			Avatar:    "",
			Message:   string(message.Plaintext),
			Timestamp: message.Timestamp,
		}
		conversationModel.AddMessage(msg)
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
	client.SendMessage(nickname, []byte(message))
	var m = NewMessage(nil)
	m.Nickname = accountBridge.Nickname()
	m.Avatar = accountBridge.Nickname()
	m.Message = message
	m.Timestamp = time.Now()
	conversationModel.AddMessage(m)
	conversations[nickname] = append(conversations[nickname], m)
}
