package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike/schemes"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

// Application states
type state int

const (
	bannerView state = iota
	menuView
	questionView
	sphinxGeometryView
	keyGenerationView
)

// Sphinx geometry configuration
type sphinxGeometryConfig struct {
	schemeType               string // "NIKE" or "KEM"
	nikeScheme               string
	kemScheme                string
	nrMixLayers              int
	userForwardPayloadLength int
	currentStep              int    // 0=scheme type, 1=scheme selection, 2=layers, 3=payload, 4=generate
	generatedGeometry        string // stores the generated TOML for printing after exit
}

// Key generation configuration
type keyGenerationConfig struct {
	keyType       string // "nike", "kem", or "sign"
	schemeName    string
	outName       string
	currentStep   int    // 0=key type, 1=scheme selection, 2=output name, 3=generate
	generatedKeys string // stores the generated key info for printing after exit
}

// Dynamic scheme lists - populated from hpqc packages
func getNikeSchemes() []list.Item {
	var items []list.Item
	for _, scheme := range schemes.All() {
		items = append(items, menuItem(scheme.Name()))
	}
	return items
}

func getKemSchemes() []list.Item {
	var items []list.Item
	for _, scheme := range kemschemes.All() {
		items = append(items, menuItem(scheme.Name()))
	}
	return items
}

func getSignSchemes() []list.Item {
	var items []list.Item
	for _, scheme := range signschemes.All() {
		items = append(items, menuItem(scheme.Name()))
	}
	return items
}

var schemeTypeOptions = []list.Item{
	menuItem("NIKE"),
	menuItem("KEM"),
}

var keyTypeOptions = []list.Item{
	menuItem("nike"),
	menuItem("kem"),
	menuItem("sign"),
}

// Main model for the wizard
type model struct {
	state        state
	list         list.Model
	choice       string
	quitting     bool
	width        int
	height       int
	sphinxConfig sphinxGeometryConfig
	keyConfig    keyGenerationConfig
	textInput    textinput.Model
	schemeList   list.Model
	err          error
}

// Banner with ANSI colors
func renderBanner() string {
	banner := lipgloss.NewStyle().
		Foreground(lipgloss.Color("205")).
		Bold(true).
		Render(`
╦╔═╔═╗╔╦╗╔═╗╔═╗╔╗╔╔═╗╔═╗╔═╗╔╦╗
╠╩╗╠═╣ ║ ╔═╝║╣ ║║║╠═╝║ ║╚═╗ ║
╩ ╩╩ ╩ ╩ ╚═╝╚═╝╝╚╝╩  ╚═╝╚═╝ ╩

    Mixnet Configuration Wizard
`)

	subtitle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240")).
		Render("\n    Welcome to the Katzenpost setup wizard\n    Press any key to continue...")

	return banner + subtitle
}

// Menu items for the wizard
type menuItem string

func (i menuItem) FilterValue() string { return "" }

// Custom delegate for menu items
type menuDelegate struct{}

func (d menuDelegate) Height() int                             { return 1 }
func (d menuDelegate) Spacing() int                            { return 0 }
func (d menuDelegate) Update(_ tea.Msg, _ *list.Model) tea.Cmd { return nil }
func (d menuDelegate) Render(w io.Writer, m list.Model, index int, listItem list.Item) {
	i, ok := listItem.(menuItem)
	if !ok {
		return
	}

	str := fmt.Sprintf("%d. %s", index+1, i)

	// Styling
	itemStyle := lipgloss.NewStyle().PaddingLeft(4)
	selectedItemStyle := lipgloss.NewStyle().
		PaddingLeft(2).
		Foreground(lipgloss.Color("170")).
		Bold(true)

	fn := itemStyle.Render
	if index == m.Index() {
		fn = func(s ...string) string {
			return selectedItemStyle.Render("▶ " + strings.Join(s, " "))
		}
	}

	fmt.Fprint(w, fn(str))
}

// Menu options
var menuItems = []list.Item{
	menuItem("Setup Directory Authority node"),
	menuItem("Setup Mix node"),
	menuItem("Setup Service node"),
	menuItem("Setup Gateway node"),
	menuItem("Setup storage Replica node"),
	menuItem("Setup client"),
	menuItem("Generate keys"),
	menuItem("Generate sphinx geometry"),
	menuItem("Exit"),
}

// Initialize the model
func initialModel() model {
	// Create the list for menu with our custom delegate
	l := list.New(menuItems, menuDelegate{}, 0, 0)
	l.Title = "What would you like to do?"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)

	// Style the list
	l.Styles.Title = lipgloss.NewStyle().
		MarginLeft(2).
		MarginBottom(1).
		Foreground(lipgloss.Color("205")).
		Bold(true)

	return model{
		state: bannerView,
		list:  l,
	}
}

// Init is called when the program starts
func (m model) Init() tea.Cmd {
	return nil
}

// Update handles messages and updates the model
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.list.SetWidth(msg.Width)
		m.list.SetHeight(msg.Height - 4) // Leave space for title
		return m, nil

	case tea.KeyMsg:
		switch m.state {
		case bannerView:
			// Any key moves from banner to menu
			m.state = menuView
			return m, nil

		case menuView:
			switch msg.String() {
			case "q", "ctrl+c":
				m.quitting = true
				return m, tea.Quit
			case "enter":
				i, ok := m.list.SelectedItem().(menuItem)
				if ok {
					m.choice = string(i)
					if m.choice == "Exit" {
						m.quitting = true
						return m, tea.Quit
					} else if m.choice == "Generate sphinx geometry" {
						// Initialize sphinx geometry configuration
						m.state = sphinxGeometryView
						m.sphinxConfig = sphinxGeometryConfig{
							nrMixLayers:              3,    // default
							userForwardPayloadLength: 2000, // default
							currentStep:              0,    // start with scheme type selection
						}
						// Initialize the scheme type selection list
						m.schemeList = list.New(schemeTypeOptions, menuDelegate{}, 0, 0)
						m.schemeList.Title = "Choose Sphinx scheme type:"
						m.schemeList.SetShowStatusBar(false)
						m.schemeList.SetFilteringEnabled(false)
						return m, nil
					} else if m.choice == "Generate keys" {
						// Initialize key generation configuration
						m.state = keyGenerationView
						m.keyConfig = keyGenerationConfig{
							outName:     "out", // default
							currentStep: 0,     // start with key type selection
						}
						// Initialize the key type selection list
						m.schemeList = list.New(keyTypeOptions, menuDelegate{}, 0, 0)
						m.schemeList.Title = "Choose key type:"
						m.schemeList.SetShowStatusBar(false)
						m.schemeList.SetFilteringEnabled(false)
						return m, nil
					}
					// For other choices, just show the choice and quit for now
					return m, tea.Quit
				}
			}

		case sphinxGeometryView:
			return m.updateSphinxGeometry(msg)
		}
	}

	// Update the list if we're in menu view
	if m.state == menuView {
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	}

	return m, nil
}

// updateSphinxGeometry handles sphinx geometry configuration
func (m model) updateSphinxGeometry(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.schemeList.SetWidth(msg.Width)
		m.schemeList.SetHeight(msg.Height - 6)
		m.textInput.Width = msg.Width - 4
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "esc":
			// Go back to main menu
			m.state = menuView
			return m, nil
		case "enter":
			return m.handleSphinxGeometryStep()
		}

		// Handle input based on current step
		switch m.sphinxConfig.currentStep {
		case 0, 1: // scheme type or scheme selection - use list
			var cmd tea.Cmd
			m.schemeList, cmd = m.schemeList.Update(msg)
			return m, cmd
		case 2, 3: // numeric input - use text input
			// Don't pass Enter to text input, let it be handled above
			if msg.String() != "enter" {
				var cmd tea.Cmd
				m.textInput, cmd = m.textInput.Update(msg)
				return m, cmd
			}
		}
	}
	return m, nil
}

// handleSphinxGeometryStep processes the current step in sphinx geometry configuration
func (m model) handleSphinxGeometryStep() (tea.Model, tea.Cmd) {
	switch m.sphinxConfig.currentStep {
	case 0: // Scheme type selection (NIKE or KEM)
		if selected, ok := m.schemeList.SelectedItem().(menuItem); ok {
			m.sphinxConfig.schemeType = string(selected)
			m.sphinxConfig.currentStep = 1

			// Setup scheme selection list based on type
			var schemes []list.Item
			if m.sphinxConfig.schemeType == "NIKE" {
				schemes = getNikeSchemes()
				m.schemeList.Title = "Choose NIKE scheme:"
			} else {
				schemes = getKemSchemes()
				m.schemeList.Title = "Choose KEM scheme:"
			}

			m.schemeList = list.New(schemes, menuDelegate{}, m.width, m.height-6)
			m.schemeList.SetShowStatusBar(false)
			m.schemeList.SetFilteringEnabled(false)
		}

	case 1: // Specific scheme selection
		if selected, ok := m.schemeList.SelectedItem().(menuItem); ok {
			if m.sphinxConfig.schemeType == "NIKE" {
				m.sphinxConfig.nikeScheme = string(selected)
			} else {
				m.sphinxConfig.kemScheme = string(selected)
			}
			m.sphinxConfig.currentStep = 2

			// Setup text input for mix layers
			m.textInput = textinput.New()
			m.textInput.Placeholder = "3"
			m.textInput.Focus()
			m.textInput.CharLimit = 2
			m.textInput.Width = 20
		}

	case 2: // Number of mix layers
		if m.textInput.Value() != "" {
			if layers, err := strconv.Atoi(m.textInput.Value()); err == nil && layers > 0 {
				m.sphinxConfig.nrMixLayers = layers
				m.sphinxConfig.currentStep = 3

				// Setup text input for payload length
				m.textInput = textinput.New()
				m.textInput.Placeholder = "2000"
				m.textInput.Focus()
				m.textInput.CharLimit = 6
				m.textInput.Width = 20
			} else {
				m.err = fmt.Errorf("invalid number of mix layers")
			}
		} else {
			// Use default
			m.sphinxConfig.nrMixLayers = 3
			m.sphinxConfig.currentStep = 3

			// Setup text input for payload length
			m.textInput = textinput.New()
			m.textInput.Placeholder = "2000"
			m.textInput.Focus()
			m.textInput.CharLimit = 6
			m.textInput.Width = 20
		}

	case 3: // User forward payload length
		if m.textInput.Value() != "" {
			if payload, err := strconv.Atoi(m.textInput.Value()); err == nil && payload > 0 {
				m.sphinxConfig.userForwardPayloadLength = payload
			} else {
				m.err = fmt.Errorf("invalid payload length")
				return m, nil
			}
		} else {
			// Use default
			m.sphinxConfig.userForwardPayloadLength = 2000
		}

		// Generate the geometry
		return m.generateSphinxGeometry()
	}

	return m, nil
}

// generateSphinxGeometry creates and displays the sphinx geometry
func (m model) generateSphinxGeometry() (tea.Model, tea.Cmd) {
	nrHops := m.sphinxConfig.nrMixLayers + 2

	var sphinxGeometry *geo.Geometry

	if m.sphinxConfig.schemeType == "NIKE" {
		nikeScheme := schemes.ByName(m.sphinxConfig.nikeScheme)
		if nikeScheme == nil {
			m.err = fmt.Errorf("failed to resolve NIKE scheme %s", m.sphinxConfig.nikeScheme)
			return m, nil
		}

		sphinxGeometry = geo.GeometryFromUserForwardPayloadLength(
			nikeScheme,
			m.sphinxConfig.userForwardPayloadLength,
			true,
			nrHops,
		)
	} else { // KEM
		kemScheme := kemschemes.ByName(m.sphinxConfig.kemScheme)
		if kemScheme == nil {
			m.err = fmt.Errorf("failed to resolve KEM scheme %s", m.sphinxConfig.kemScheme)
			return m, nil
		}

		sphinxGeometry = geo.KEMGeometryFromUserForwardPayloadLength(
			kemScheme,
			m.sphinxConfig.userForwardPayloadLength,
			true,
			nrHops,
		)
	}

	if sphinxGeometry == nil {
		m.err = fmt.Errorf("failed to generate sphinx geometry")
		return m, nil
	}

	// Store the geometry for printing after bubbletea exits
	m.sphinxConfig.generatedGeometry = sphinxGeometry.Display()

	// Exit after generating - geometry will be printed in main()
	m.quitting = true
	return m, tea.Quit
}

// View renders the current view
func (m model) View() string {
	switch m.state {
	case bannerView:
		return renderBanner()
	case menuView:
		if m.quitting {
			return lipgloss.NewStyle().Margin(1, 0, 2, 4).Render("Goodbye!")
		}
		return "\n" + m.list.View()
	case sphinxGeometryView:
		return m.renderSphinxGeometryView()
	default:
		return "Unknown state"
	}
}

// renderSphinxGeometryView renders the sphinx geometry configuration screen
func (m model) renderSphinxGeometryView() string {
	if m.err != nil {
		return fmt.Sprintf("Error: %v\n\nPress 'q' to quit or 'esc' to go back", m.err)
	}

	title := lipgloss.NewStyle().
		Foreground(lipgloss.Color("205")).
		Bold(true).
		Render("Generate Sphinx Geometry")

	var content string

	switch m.sphinxConfig.currentStep {
	case 0: // Scheme type selection
		content = "\nStep 1/4: Choose the cryptographic scheme type\n\n" + m.schemeList.View()

	case 1: // Specific scheme selection
		schemeType := m.sphinxConfig.schemeType
		content = fmt.Sprintf("\nStep 2/4: Choose the %s scheme\n\n", schemeType) + m.schemeList.View()

	case 2: // Mix layers input
		content = fmt.Sprintf("\nStep 3/4: Number of mix routing layers\n\n"+
			"Current selection:\n"+
			"• Scheme Type: %s\n"+
			"• Scheme: %s\n\n"+
			"Enter number of mix layers (default: 3): %s\n\n"+
			"Press Enter to continue, Esc to go back",
			m.sphinxConfig.schemeType,
			m.getSelectedScheme(),
			m.textInput.View())

	case 3: // Payload length input
		content = fmt.Sprintf("\nStep 4/4: User forward payload length\n\n"+
			"Current selection:\n"+
			"• Scheme Type: %s\n"+
			"• Scheme: %s\n"+
			"• Mix Layers: %d\n\n"+
			"Enter payload length in bytes (default: 2000): %s\n\n"+
			"Press Enter to generate geometry, Esc to go back",
			m.sphinxConfig.schemeType,
			m.getSelectedScheme(),
			m.sphinxConfig.nrMixLayers,
			m.textInput.View())
	}

	instructions := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240")).
		Render("\nUse ↑/↓ or j/k to navigate, Enter to select, Esc to go back, q to quit")

	return title + content + instructions
}

// getSelectedScheme returns the currently selected scheme name
func (m model) getSelectedScheme() string {
	if m.sphinxConfig.schemeType == "NIKE" {
		return m.sphinxConfig.nikeScheme
	}
	return m.sphinxConfig.kemScheme
}

func main() {
	// Initialize the program WITHOUT alt screen so it doesn't clear on exit
	p := tea.NewProgram(initialModel())
	finalModel, err := p.Run()
	if err != nil {
		fmt.Printf("Error running wizard: %v\n", err)
		os.Exit(1)
	}

	// Print geometry if it was generated
	if m, ok := finalModel.(model); ok && m.sphinxConfig.generatedGeometry != "" {
		fmt.Printf("\n\n\n%s\n\n", m.sphinxConfig.generatedGeometry)
	}
}
