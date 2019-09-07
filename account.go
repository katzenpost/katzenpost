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
func loadConversation(contact string) {
	conversationModel.Clear()
	accountBridge.SetRecipient(contact)

	_, ok := conversations[contact]
	if !ok {
		{
			var message = NewMessage(nil)
			message.Nickname = contact
			message.Message = "Hi there, this is a test!"
			message.Timestamp = time.Now().Add(-8 * time.Hour)
			conversations[contact] = append(conversations[contact], message)
		}
		{
			var message = NewMessage(nil)
			message.Nickname = accountBridge.Nickname()
			message.Avatar = accountBridge.Avatar()
			message.Message = "This is a reply!"
			message.Timestamp = time.Now()
			conversations[contact] = append(conversations[contact], message)
		}
	}

	for _, msg := range conversations[contact] {
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
