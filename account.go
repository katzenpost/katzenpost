package main

// loadAccount loads the meta-data associated with an account
func loadAccount() {
	accountBridge.SetNickname("muesli")
	accountBridge.SetAvatar("https://picsum.photos/128/128")
}

// loadContactList loads the contact list for an account
func loadContactList(contactListModel *ContactListModel) {
	{
		var contact = NewContact(nil)
		contact.Nickname = "some user"
		contact.Avatar = "https://picsum.photos/128/128"
		contactListModel.AddContact(contact)
	}
	{
		var contact = NewContact(nil)
		contact.Nickname = "another user"
		contact.Avatar = "https://picsum.photos/129/129"
		contactListModel.AddContact(contact)
	}
}

// loadConversation loads the conversation with a contact
func loadConversation(contact string) {
	{
		var message = NewMessage(nil)
		message.Nickname = contact
		message.Avatar = "https://picsum.photos/129/129"
		message.Message = "Hi there, this is a test!"
		conversationModel.AddMessage(message)
	}
	{
		var message = NewMessage(nil)
		message.Nickname = accountBridge.Nickname()
		message.Avatar = "https://picsum.photos/130/130"
		message.Message = "This is a reply!"
		conversationModel.AddMessage(message)
	}
}

// addContact adds a contact to the contact list
func addContact(passphrase string, nickname string) bool {
	var c = NewContact(nil)
	c.Nickname = nickname
	c.Avatar = "https://picsum.photos/140/140"
	contactListModel.AddContact(c)

	return true
}

// sendMessage sends a message to a contact
func sendMessage(recipient string, message string) {
	/*
		err := backend.SendMessage()
		if err != nil {
			accountBridge.SetError(err)
			return
		}
	*/

	var m = NewMessage(nil)
	m.Nickname = accountBridge.Nickname()
	m.Avatar = "https://picsum.photos/130/130"
	m.Message = message
	conversationModel.AddMessage(m)
}
