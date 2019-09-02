package main

import (
	"os"

	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/qml"
	"github.com/therecipe/qt/quickcontrols2"

	gap "github.com/muesli/go-app-paths"
)

var (
	config     Config
	configFile string

	contactListModel  = NewContactListModel(nil)
	conversationModel = NewConversationModel(nil)
)

func addContact(contact string, nickname string) bool {
	var c = NewContact(nil)
	c.Nickname = nickname
	c.Avatar = "https://picsum.photos/140/140"
	contactListModel.AddContact(c)

	return true
}

func sendMessage(recipient string, message string) {
	/*
		err := backend.SendMessage()
		if err != nil {
			accountBridge.SetError(err)
			return
		}
	*/

	var m = NewMessage(nil)
	m.Nickname = "me"
	m.Avatar = "https://picsum.photos/130/130"
	m.Message = message
	conversationModel.AddMessage(m)
}

// runApp loads and executes the QML UI
func runApp(config Config) {
	var theme string
	switch config.Theme {
	case "System":
		theme = ""
	case "Light":
		theme = "Default"
	default:
		theme = config.Theme
	}
	if theme != "" {
		quickcontrols2.QQuickStyle_SetStyle(theme)
	}

	app := qml.NewQQmlApplicationEngine(nil)
	app.RootContext().SetContextProperty("uiBridge", uiBridge)
	app.RootContext().SetContextProperty("accountBridge", accountBridge)
	app.RootContext().SetContextProperty("settings", configBridge)

	app.Load(core.NewQUrl3("qrc:/qml/catchat.qml", 0))
	gui.QGuiApplication_Exec()
}

func loadAccount() {
	accountBridge.SetNickname("muesli")
	accountBridge.SetAvatar("https://picsum.photos/128/128")
}

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

func loadConversation(contact string) {
	{
		var message = NewMessage(nil)
		message.Nickname = "another user"
		message.Avatar = "https://picsum.photos/129/129"
		message.Message = "Hi there, this is a test!"
		conversationModel.AddMessage(message)
	}
	{
		var message = NewMessage(nil)
		message.Nickname = "me"
		message.Avatar = "https://picsum.photos/130/130"
		message.Message = "This is a reply!"
		conversationModel.AddMessage(message)
	}
}

func main() {
	core.QCoreApplication_SetApplicationName("catchat")
	core.QCoreApplication_SetOrganizationName("katzenpost")
	core.QCoreApplication_SetAttribute(core.Qt__AA_EnableHighDpiScaling, true)

	_ = gui.NewQGuiApplication(len(os.Args), os.Args)
	// ga.SetWindowIcon(gui.NewQIcon5(":/qml/images/icon.png"))
	setupQmlBridges()

	// load config
	scope := gap.NewScope(gap.User, "katzenpost", "catchat")
	configDir, err := scope.ConfigPath("")
	if err != nil {
		panic(err)
	}
	os.MkdirAll(configDir, 0700)

	configFile, err = scope.ConfigPath("catchat.conf")
	if err != nil {
		panic(err)
	}
	config = LoadConfig(configFile)
	if config.Theme == "" {
		config.Theme = "Material"
	}
	if config.Style == "" {
		config.Style = "Dark"
	}
	configBridge.SetTheme(config.Theme)
	configBridge.SetStyle(config.Style)
	configBridge.SetFirstRun(config.FirstRun)
	configBridge.SetPositionX(config.PositionX)
	configBridge.SetPositionY(config.PositionY)
	configBridge.SetWidth(config.Width)
	configBridge.SetHeight(config.Height)

	loadAccount()
	loadContactList(contactListModel)

	accountBridge.SetContactListModel(contactListModel)
	accountBridge.SetConversationModel(conversationModel)
	runApp(config)

	// save config
	config.Theme = configBridge.Theme()
	config.Style = configBridge.Style()
	config.PositionX = configBridge.PositionX()
	config.PositionY = configBridge.PositionY()
	config.Width = configBridge.Width()
	config.Height = configBridge.Height()
	config.FirstRun = false
	SaveConfig(configFile, config)
}
