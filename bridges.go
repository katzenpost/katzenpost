package main

import (
	"github.com/therecipe/qt/core"
)

// AccountBridge makes an account available in QML
type AccountBridge struct {
	core.QObject

	_ string `property:"nickname"`
	_ string `property:"avatar"`
	_ string `property:"error"`

	_ func(passphrase string, nickname string) bool `slot:"addContact"`
	_ func(contact string)                          `slot:"loadConversation"`
	_ func(recipient string, message string)        `slot:"sendMessage"`

	_ *core.QAbstractListModel `property:"contactListModel"`
	_ *core.QAbstractListModel `property:"conversationModel"`
}

// ConfigBridge allows QML to access the app's config
type ConfigBridge struct {
	core.QObject

	_ bool   `property:"firstRun"`
	_ string `property:"authURL"`
	_ string `property:"redirectURL"`
	_ string `property:"theme"`
	_ string `property:"style"`
	_ int    `property:"positionX"`
	_ int    `property:"positionY"`
	_ int    `property:"width"`
	_ int    `property:"height"`
}

var (
	accountBridge *AccountBridge
	configBridge  *ConfigBridge
)

// setupQmlBridges initializes the QML bridges
func setupQmlBridges() {
	accountBridge = NewAccountBridge(nil)
	configBridge = NewConfigBridge(nil)

	accountBridge.ConnectAddContact(addContact)
	accountBridge.ConnectLoadConversation(loadConversation)
	accountBridge.ConnectSendMessage(sendMessage)
}
