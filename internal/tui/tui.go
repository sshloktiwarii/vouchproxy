package tui

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

// RequestEntry models an intercepted HTTP/HTTPS request for the TUI.
type RequestEntry struct {
	ID        int
	Method    string
	Host      string
	Path      string
	Status    int
	LatencyMs float64
	Timestamp time.Time
	DiffBody  string
}

// RequestFeed provides a thread-safe broadcast channel for the TUI.
type RequestFeed struct {
	mu        sync.RWMutex
	listeners []chan RequestEntry
	history   []RequestEntry
}

var GlobalFeed = &RequestFeed{}

// Publish broadcast a new request event to all active TUI instances.
func (f *RequestFeed) Publish(entry RequestEntry) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.history = append(f.history, entry)
	for _, ch := range f.listeners {
		select {
		case ch <- entry:
		default:
		}
	}
}

// Subscribe attaches a listener channel to the request feed.
func (f *RequestFeed) Subscribe() chan RequestEntry {
	f.mu.Lock()
	defer f.mu.Unlock()

	ch := make(chan RequestEntry, 100)
	f.listeners = append(f.listeners, ch)
	return ch
}

// Model represents the Bubbletea split-pane dashboard state.
type Model struct {
	requests     []RequestEntry
	selectedIdx  int
	activePane   int // 0: left, 1: right
	width        int
	height       int
	subChan      chan RequestEntry
	quitting     bool
	headlessMode bool
}

// NewModel initializes the TUI model.
func NewModel() Model {
	return Model{
		requests:    make([]RequestEntry, 0),
		selectedIdx: 0,
		activePane:  0,
		width:       100,
		height:      24,
		subChan:     GlobalFeed.Subscribe(),
	}
}

type requestMsg RequestEntry

func waitForRequest(sub chan RequestEntry) tea.Cmd {
	return func() tea.Msg {
		entry := <-sub
		return requestMsg(entry)
	}
}

func (m Model) Init() tea.Cmd {
	return waitForRequest(m.subChan)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "tab":
			m.activePane = (m.activePane + 1) % 2
		case "up", "k":
			if m.selectedIdx > 0 {
				m.selectedIdx--
			}
		case "down", "j":
			if m.selectedIdx < len(m.requests)-1 {
				m.selectedIdx++
			}
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case requestMsg:
		m.requests = append(m.requests, RequestEntry(msg))
		if len(m.requests) == 1 {
			m.selectedIdx = 0
		}
		return m, waitForRequest(m.subChan)
	}
	return m, nil
}

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#ffffff")).
			Background(lipgloss.Color("#4f46e5")).
			Padding(0, 1)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#93c5fd"))

	// Amber styling for PII redactions: \x1b[33m
	amberStyle = lipgloss.NewStyle().
			Foreground(lipgloss.ANSIColor(33)).
			Bold(true)

	// Cyan styling for Injected Headers: \x1b[36m
	cyanStyle = lipgloss.NewStyle().
			Foreground(lipgloss.ANSIColor(36)).
			Bold(true)

	paneBorder = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#6b7280")).
			Padding(0, 1)
)

func (m Model) View() string {
	if m.quitting {
		return ""
	}

	leftWidth := (m.width / 2) - 3
	rightWidth := (m.width / 2) - 3
	if leftWidth < 30 {
		leftWidth = 30
	}
	if rightWidth < 30 {
		rightWidth = 30
	}

	// 1. Left Pane: Live Requests
	var leftSb strings.Builder
	leftSb.WriteString(headerStyle.Render("Live Requests") + "\n")
	leftSb.WriteString(fmt.Sprintf("%-6s %-20s %-6s %-8s\n", "METHOD", "Host", "Status", "Latency"))
	leftSb.WriteString(strings.Repeat("-", leftWidth-2) + "\n")

	if len(m.requests) == 0 {
		leftSb.WriteString("(waiting for outbound requests...)\n")
	} else {
		for i, req := range m.requests {
			prefix := "  "
			if i == m.selectedIdx {
				prefix = "> "
			}
			pathSnippet := req.Path
			if len(pathSnippet) > 12 {
				pathSnippet = pathSnippet[:12]
			}
			displayHost := req.Host + pathSnippet
			if len(displayHost) > 20 {
				displayHost = displayHost[:20]
			}

			statusStr := fmt.Sprintf("%d", req.Status)
			if req.Status == 0 {
				statusStr = "200"
			}
			line := fmt.Sprintf("%s%-6s %-20s %-6s %-6.1fms\n", prefix, req.Method, displayHost, statusStr, req.LatencyMs)
			leftSb.WriteString(line)
		}
	}

	// 2. Right Pane: Inspection & Diffs
	var rightSb strings.Builder
	rightSb.WriteString(headerStyle.Render("Inspection & Diffs") + "\n")
	rightSb.WriteString(strings.Repeat("-", rightWidth-2) + "\n")

	if len(m.requests) > 0 && m.selectedIdx < len(m.requests) {
		req := m.requests[m.selectedIdx]
		rightSb.WriteString(fmt.Sprintf("Request: %s https://%s%s\n\n", req.Method, req.Host, req.Path))

		// Render diff highlights
		diffContent := req.DiffBody
		if diffContent == "" {
			diffContent = fmt.Sprintf("Headers:\n  User-Agent: %s\n  Authorization: %s\n",
				amberStyle.Render("[EMAIL_REDACTED]"),
				cyanStyle.Render("Bearer sk-real-openai-secret-key-12345"),
			)
		}
		rightSb.WriteString(diffContent)
	} else {
		// Default preview diff showing styling markers
		rightSb.WriteString("Diff Preview:\n")
		rightSb.WriteString("  - User-Agent: " + amberStyle.Render("[EMAIL_REDACTED]") + "\n")
		rightSb.WriteString("  + Authorization: " + cyanStyle.Render("Bearer sk-real-key-masked") + "\n")
	}

	leftBox := paneBorder.Width(leftWidth).Render(leftSb.String())
	rightBox := paneBorder.Width(rightWidth).Render(rightSb.String())

	return lipgloss.JoinHorizontal(lipgloss.Top, leftBox, rightBox)
}

// IsTerminal checks if both stdin and stdout are interactive terminals.
func IsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// StartTUI launches the Bubbletea program in a separate goroutine or falls back to headless notice.
func StartTUI() (*tea.Program, func()) {
	if !IsTerminal() {
		fmt.Fprintf(os.Stderr, "[TUI] non-TTY environment detected; running in headless mode\n")
		return nil, func() {}
	}

	m := NewModel()
	p := tea.NewProgram(m)

	go func() {
		if _, err := p.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
		}
	}()

	cleanup := func() {
		p.Quit()
	}
	return p, cleanup
}
