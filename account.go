package main

import (
	"sort"
	"time"

	"github.com/katzenpost/catshadow"
)

// loadContactList loads the contact list for an account
func loadContactList(contactListModel *ContactListModel, contacts map[string]*catshadow.Contact) {
	for _, c := range contacts {
		var contact = NewContact(nil)
		contact.Nickname = c.Nickname
		contact.KeyExchanged = !c.IsPending
		// XXX contact.Avatar = "https://picsum.photos/128/128"
		contactListModel.AddContact(contact)
	}
}

// loadConversation loads the conversation with a contact
func loadConversation(client *catshadow.Client, contact string) {
	c := contactListModel.getContact(contact)
	if c == nil {
		panic("Could not find unknown contact with name: " + contact)
	}

	accountBridge.SetRecipient(c.Nickname)
	accountBridge.SetKeyExchanged(c.KeyExchanged)

	conversationModel.Clear()
	conversation := client.GetConversation(contact)

	var msgs Messages
	for _, message := range conversation {
		var m = NewMessage(nil)

		if message.Outbound {
			m.Nickname = accountBridge.Nickname()
		} else {
			m.Nickname = c.Nickname
		}

		m.Avatar = ""
		m.Message = string(message.Plaintext)
		m.Timestamp = message.Timestamp
		m.Outbound = message.Outbound

		msgs = append(msgs, m)
	}

	sort.Sort(msgs)

	for _, m := range msgs {
		conversationModel.AppendMessage(m)
	}
}

// addContact adds a contact to the contact list
func addContact(client *catshadow.Client, nickname string, passphrase string) bool {
	for _, v := range contactListModel.Contacts() {
		if v.Nickname == nickname {
			// name already taken
			return false
		}
	}

	client.NewContact(nickname, []byte(passphrase))

	var c = NewContact(nil)
	c.Nickname = nickname
	c.Avatar = ""
	contactListModel.AddContact(c)

	return true
}

// removeContact removes a contact from the contact list
func removeContact(client *catshadow.Client, nickname string) bool {
	for i, v := range contactListModel.Contacts() {
		if v.Nickname == nickname {
			client.RemoveContact(nickname)
			contactListModel.RemoveContact(i)
			return true
		}
	}
	return false
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
	conversationModel.AppendMessage(m)
}
