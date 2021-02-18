package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/katzenpost/catshadow"
	catconfig "github.com/katzenpost/catshadow/config"
	"github.com/katzenpost/client"
	clientConfig "github.com/katzenpost/client/config"
	gap "github.com/muesli/go-app-paths"
	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/qml"
	"github.com/therecipe/qt/quickcontrols2"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	initialPKIConsensusTimeout = 45 * time.Second
)

var (
	config Config

	generate         = flag.Bool("g", false, "Generate the state file and then run client.")
	clientConfigFile = flag.String("f", "", "Path to the client config file.")
	stateFile        = flag.String("s", "catshadow_statefile", "The catshadow state file path.")

	catShadowClient   *catshadow.Client
	catshadowCfg      *catconfig.Config
	contactListModel  *ContactListModel
	conversationModel *ConversationModel
)

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
	app.RootContext().SetContextProperty("accountBridge", accountBridge)
	app.RootContext().SetContextProperty("settings", configBridge)

	app.Load(core.NewQUrl3("qrc:/qml/catchat.qml", 0))
	gui.QGuiApplication_Exec()
}

func setupCatShadow(catshadowCfg *catconfig.Config, passphrase []byte) {
	var stateWorker *catshadow.StateWriter
	var state *catshadow.State
	cfg, err := catshadowCfg.ClientConfig()
	if err != nil {
		panic(err)
	}
	if *generate {
		if _, err := os.Stat(*stateFile); !os.IsNotExist(err) {
			panic("cannot generate state file, already exists")
		}

		cfg, linkKey := client.AutoRegisterRandomClient(cfg)
		c, err := client.New(cfg)
		if err != nil {
			panic(err)
		}

		// Create statefile.
		stateWorker, err = catshadow.NewStateWriter(c.GetLogger("catshadow_state"), *stateFile, passphrase)
		if err != nil {
			panic(err)
		}
		// Start the stateworker
		stateWorker.Start()
		fmt.Println("creating remote message receiver spool")
		backendLog, err := catshadowCfg.InitLogBackend()
		if err != nil {
			panic(err)
		}

		user := fmt.Sprintf("%x", linkKey.PublicKey().Bytes())
		catShadowClient, err = catshadow.NewClientAndRemoteSpool(backendLog, c, stateWorker, user, linkKey)
		if err != nil {
			panic(err)
		}
		fmt.Println("catshadow client successfully created")
	} else {
		cfg, _ := client.AutoRegisterRandomClient(cfg)

		// Load previous state to setup our current client state.
		backendLog, err := catshadowCfg.InitLogBackend()
		if err != nil {
			panic(err)
		}
		stateWorker, state, err = catshadow.LoadStateWriter(backendLog.GetLogger("state_worker"), *stateFile, passphrase)
		if err != nil {
			panic(err)
		}
		// Start the stateworker
		stateWorker.Start()
		cfg.Account = &clientConfig.Account{
			User:     state.User,
			Provider: state.Provider,
		}

		// Run a Client.
		c, err := client.New(cfg)
		if err != nil {
			panic(err)
		}

		// Make a catshadow Client.
		catShadowClient, err = catshadow.New(backendLog, c, stateWorker, state)
		if err != nil {
			panic(err)
		}
	}

	// Start catshadow client.
	catShadowClient.Start()

	go eventLoop(catShadowClient.EventSink, conversationModel, contactListModel)

	contacts := catShadowClient.GetContacts()
	loadContactList(contactListModel, contacts)
}

func main() {
	flag.Parse()

	// Set the umask to something "paranoid".
	syscall.Umask(0077)

	fmt.Println("Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.")

	core.QCoreApplication_SetApplicationName("catchat")
	core.QCoreApplication_SetOrganizationName("katzenpost")
	core.QCoreApplication_SetAttribute(core.Qt__AA_EnableHighDpiScaling, true)

	ga := gui.NewQGuiApplication(len(os.Args), os.Args)
	ga.SetWindowIcon(gui.NewQIcon5(":/qml/images/katzenpost_logo.png"))

	// load config
	scope := gap.NewScope(gap.User, "catchat")
	configDir, err := scope.ConfigPath("")
	if err != nil {
		panic(err)
	}
	os.MkdirAll(configDir, 0700)
	dataDir, err := scope.DataDirs()
	if err != nil {
		panic(err)
	}
	os.MkdirAll(dataDir[0], 0700)
	configFile, err := scope.ConfigPath("catchat.conf")
	if err != nil {
		panic(err)
	}
	config = LoadConfig(configFile)

	// Prepare catshadow client instance.
	contactListModel = NewContactListModel(nil)
	conversationModel = NewConversationModel(nil)

	// Load catshadow config file if specified or use baked-in defaults
	if len(*clientConfigFile) != 0 {
		catshadowCfg, err = catconfig.LoadFile(*clientConfigFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load config file '%v': %v\n", *clientConfigFile, err)
			os.Exit(-1)
		}
	} else {
		// use the baked in configuration defaults if a configuration is not specified
		catshadowCfg, err = getDefaultConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load config defaults: %v\n", err)
			os.Exit(-1)
		}
	}

	// Decrypt and load the catshadow state file.
	fmt.Print("Enter statefile decryption passphrase: ")
	passphrase, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err)
	}
	fmt.Println()

	go setupCatShadow(catshadowCfg, passphrase)

	// Start graphical user interface.
	setupQmlBridges()

	configBridge.SetTheme(config.Theme)
	configBridge.SetStyle(config.Style)
	configBridge.SetNotification(config.Notification)
	configBridge.SetFirstRun(config.FirstRun)
	configBridge.SetPositionX(config.PositionX)
	configBridge.SetPositionY(config.PositionY)
	configBridge.SetWidth(config.Width)
	configBridge.SetHeight(config.Height)

	accountBridge.SetContactListModel(contactListModel)
	accountBridge.SetConversationModel(conversationModel)

	runApp(config)

	// Shutdown client after graphical user interface is halted.
	catShadowClient.Shutdown()

	// Save Qt user interface config on clean shutdown.
	config.Theme = configBridge.Theme()
	config.Style = configBridge.Style()
	config.Notification = configBridge.Notification()
	config.PositionX = configBridge.PositionX()
	config.PositionY = configBridge.PositionY()
	config.Width = configBridge.Width()
	config.Height = configBridge.Height()
	config.FirstRun = false

	SaveConfig(configFile, config)
}

func getDefaultConfig() (*catconfig.Config, error) {
	cfgString := `
[UpstreamProxy]
  Type = "socks5"
  Network = "tcp"
  Address = "127.0.0.1:9050"

[Logging]
  Disable = false
  Level = "DEBUG"
  File = ""

[ClientLogging]
  Disable = false
  Level = "NOTICE"
  File = ""

[VotingAuthority]
[[VotingAuthority.Peers]]
  Addresses = ["n5axysudjvjjkpy4r7hur7qfgybfaiwrfz2mqwkvnyylqxinldtao2ad.onion:30000"]
  IdentityPublicKey = "EmUWxb6ocBBXhxlrAKgxVd/6tyIDVK/8pIY/nZrqSDQ="
  LinkPublicKey = "Mcfs706pyzBIvEj+k5t2L9t9x+LplOR4wz3RiVrgoVU="

[[VotingAuthority.Peers]]
  Addresses = ["mj5ouhyjvokgvbcp56lh56plxvzh4wcrq3fadpqf6ewdqmuy7pr3n6qd.onion:30000"]
  IdentityPublicKey = "vdOAeoRtWKFDw+W4k3sNN1EMT9ZsaHHmuCHOEKSg1aA="
  LinkPublicKey = "VNmU4g1hXBS7BQ1RJYMGNjNg4fIZbCimppeJ1XwrqX4="

[[VotingAuthority.Peers]]
  Addresses = ["pz6obnsyh7vmpmtmrsam443jh4gkei77q3y66ty3fd6h6wjdvcmu6pid.onion:30000"]
  IdentityPublicKey = "bFgvws69dJrc3ACKXN5aCJKLHjkN7D8DA2HDKkhSNIk="
  LinkPublicKey = "p1JekMh8uCPDsRSP5Uc59DJvEGMmA/B0mcMCXx1WEkk="

[Debug]
  CaseSensitiveUserIdentifiers = false
  PollingInterval = 500
  PreferedTransports = ["onion"]

[Panda]
  Receiver = "+panda"
  Provider = "provider1"
  BlobSize = 1000

[Reunion]
  Enable = false
`
	return catconfig.Load([]byte(cfgString))
}
