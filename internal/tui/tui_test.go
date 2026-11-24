package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func TestRequestFeed_PublishSubscribe(t *testing.T) {
	feed := &RequestFeed{}
	sub := feed.Subscribe()

	entry := RequestEntry{
		ID:        1,
		Method:    "POST",
		Host:      "api.openai.com",
		Path:      "/v1/chat/completions",
		Status:    200,
		LatencyMs: 42.5,
		Timestamp: time.Now(),
		DiffBody:  "Authorization: Bearer ***",
	}

	feed.Publish(entry)

	select {
	case received := <-sub:
		if received.Host != "api.openai.com" {
			t.Fatalf("expected host api.openai.com, got %s", received.Host)
		}
		if received.Status != 200 {
			t.Fatalf("expected status 200, got %d", received.Status)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for feed message")
	}
}

func TestModel_InitAndUpdate(t *testing.T) {
	quitCalled := false
	m := NewModel(func() {
		quitCalled = true
	})

	// 1. Initial State
	cmd := m.Init()
	if cmd == nil {
		t.Fatal("expected non-nil tea.Cmd from Init")
	}

	// 2. Window resize message
	newM, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	model := newM.(Model)
	if model.width != 120 || model.height != 30 {
		t.Fatalf("expected dimensions 120x30, got %dx%d", model.width, model.height)
	}

	// 3. Receive new request message
	req := RequestEntry{
		ID:        1,
		Method:    "GET",
		Host:      "api.anthropic.com",
		Path:      "/v1/messages",
		Status:    200,
		LatencyMs: 15.2,
		Timestamp: time.Now(),
	}
	newM, _ = model.Update(requestMsg(req))
	model = newM.(Model)
	if len(model.requests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(model.requests))
	}
	if model.selectedIdx != 0 {
		t.Fatalf("expected selectedIdx 0, got %d", model.selectedIdx)
	}

	// 4. Keyboard navigation: Down / J
	req2 := RequestEntry{
		ID:        2,
		Method:    "POST",
		Host:      "api.github.com",
		Path:      "/graphql",
		Status:    200,
		LatencyMs: 35.0,
		Timestamp: time.Now(),
	}
	newM, _ = model.Update(requestMsg(req2))
	model = newM.(Model)

	newM, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	model = newM.(Model)
	if model.selectedIdx != 1 {
		t.Fatalf("expected selectedIdx 1 after pressing j, got %d", model.selectedIdx)
	}

	// Up / K
	newM, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	model = newM.(Model)
	if model.selectedIdx != 0 {
		t.Fatalf("expected selectedIdx 0 after pressing k, got %d", model.selectedIdx)
	}

	// Tab (pane toggle)
	newM, _ = model.Update(tea.KeyMsg{Type: tea.KeyTab})
	model = newM.(Model)
	if model.activePane != 1 {
		t.Fatalf("expected activePane 1 after tab, got %d", model.activePane)
	}

	// Quit key
	newM, quitCmd := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	model = newM.(Model)
	if !model.quitting {
		t.Fatal("expected model.quitting to be true")
	}
	if !quitCalled {
		t.Fatal("expected onQuit callback to be invoked")
	}
	if quitCmd == nil {
		t.Fatal("expected tea.Quit command")
	}
}

func TestModel_View(t *testing.T) {
	m := NewModel(nil)

	// Empty view
	view := m.View()
	if !strings.Contains(view, "Live Requests") {
		t.Fatal("expected view to contain 'Live Requests'")
	}
	if !strings.Contains(view, "waiting for outbound requests") {
		t.Fatal("expected view to indicate waiting state")
	}

	// Populated view
	req := RequestEntry{
		ID:        1,
		Method:    "GET",
		Host:      "api.openai.com",
		Path:      "/v1/models",
		Status:    200,
		LatencyMs: 25.0,
		DiffBody:  "Headers:\n  Authorization: Bearer sk-real-key-masked\n",
	}
	newM, _ := m.Update(requestMsg(req))
	model := newM.(Model)

	view = model.View()
	if !strings.Contains(view, "api.openai.com") {
		t.Fatal("expected view to contain host 'api.openai.com'")
	}
	if !strings.Contains(view, "Inspection & Diffs") {
		t.Fatal("expected view to contain 'Inspection & Diffs'")
	}

	// Quitting view returns empty string
	model.quitting = true
	if model.View() != "" {
		t.Fatal("expected empty view when quitting")
	}
}
