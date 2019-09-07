package main

import (
	"context"
	"flag"
	"fmt"
	mrand "math/rand"
	"os"
	"syscall"
	"time"

	"github.com/katzenpost/catshadow"
	catconfig "github.com/katzenpost/catshadow/config"
	"github.com/katzenpost/client"
	clientConfig "github.com/katzenpost/client/config"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/epochtime"
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
	config     Config
	configFile string

	contactListModel  = NewContactListModel(nil)
	conversationModel = NewConversationModel(nil)
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

func main() {
	generate := flag.Bool("g", false, "Generate the state file and then run client.")
	cfgFile := flag.String("f", "katzenpost.toml", "Path to the client config file.")
	stateFile := flag.String("s", "catshadow_statefile", "The catshadow state file path.")
	flag.Parse()

	// Set the umask to something "paranoid".
	syscall.Umask(0077)

	fmt.Println("Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.")

	core.QCoreApplication_SetApplicationName("catchat")
	core.QCoreApplication_SetOrganizationName("katzenpost")
	core.QCoreApplication_SetAttribute(core.Qt__AA_EnableHighDpiScaling, true)

	ga := gui.NewQGuiApplication(len(os.Args), os.Args)
	ga.SetWindowIcon(gui.NewQIcon5(":/qml/images/katzenpost_logo.png"))
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

	// Prepare catshadow client instance.

	// Load catshadow config file.
	catshadowCfg, err := catconfig.LoadFile(*cfgFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config file '%v': %v\n", *cfgFile, err)
		os.Exit(-1)
	}

	// Decrypt and load the catshadow state file.
	fmt.Print("Enter statefile decryption passphrase: ")
	passphrase, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err)
	}
	fmt.Print("\n")
	var stateWorker *catshadow.StateWriter
	var state *catshadow.State
	var catShadowClient *catshadow.Client
	cfg, err := catshadowCfg.ClientConfig()
	if err != nil {
		panic(err)
	}
	if *generate {
		if _, err := os.Stat(*stateFile); !os.IsNotExist(err) {
			panic("cannot generate state file, already exists")
		}

		// Retrieve a copy of the PKI consensus document.
		proxyCfg := cfg.UpstreamProxyConfig()
		backendLog, err := catshadowCfg.InitLogBackend()
		if err != nil {
			panic(err)
		}
		pkiClient, err := cfg.NewPKIClient(backendLog, proxyCfg)
		if err != nil {
			panic(err)
		}
		currentEpoch, _, _ := epochtime.FromUnix(time.Now().Unix())
		ctx, cancel := context.WithTimeout(context.Background(), initialPKIConsensusTimeout)
		defer cancel()
		doc, _, err := pkiClient.Get(ctx, currentEpoch)
		if err != nil {
			panic(err)
		}
		if len(doc.Providers) == 0 {
			panic("zero registration Providers found in the consensus")
		}
		provider := doc.Providers[mrand.Intn(len(doc.Providers))]

		// Connect to random Provider.
		linkKey, err := ecdh.NewKeypair(rand.Reader)
		if err != nil {
			panic(err)
		}
		user := fmt.Sprintf("%x", linkKey.Bytes())
		account := &clientConfig.Account{
			User:           user,
			Provider:       provider.Name,
			ProviderKeyPin: provider.IdentityKey,
		}
		cfg.Account = account
		c, err := client.New(cfg)
		if err != nil {
			panic(err)
		}

		// Create statefile.
		stateWorker, err = catshadow.NewStateWriter(c.GetLogger("catshadow_state"), *stateFile, passphrase)
		if err != nil {
			panic(err)
		}
		fmt.Println("creating remote message receiver spool")
		catShadowClient, err = catshadow.NewClientAndRemoteSpool(c.GetBackendLog(), c, stateWorker, user, linkKey)
		if err != nil {
			panic(err)
		}
		fmt.Println("catshadow client successfully created")
	} else {
		// Load previous state to setup our current client state.
		backendLog, err := catshadowCfg.InitLogBackend()
		if err != nil {
			panic(err)
		}
		stateWorker, state, err = catshadow.LoadStateWriter(backendLog.GetLogger("state_worker"), *stateFile, passphrase)
		if err != nil {
			panic(err)
		}
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
		catShadowClient, err = catshadow.New(c.GetBackendLog(), c, stateWorker, state)
		if err != nil {
			panic(err)
		}
	}

	// Start catshadow client.
	stateWorker.Start()
	catShadowClient.Start()

	// Start graphical user interface.
	nickNames := catShadowClient.GetNicknames()
	loadContactList(contactListModel, nickNames)
	accountBridge.SetContactListModel(contactListModel)
	accountBridge.SetConversationModel(conversationModel)
	runApp(config)

	// Shutdown client after graphical user interface is halted.
	catShadowClient.Shutdown()

	// Save QT user interface config on clean shutdown.
	config.Theme = configBridge.Theme()
	config.Style = configBridge.Style()
	config.PositionX = configBridge.PositionX()
	config.PositionY = configBridge.PositionY()
	config.Width = configBridge.Width()
	config.Height = configBridge.Height()
	config.FirstRun = false
	SaveConfig(configFile, config)
}
