package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"mcwatch/internal/protocol"
)

const maxConsoleLines = 5000

type preferences struct {
	Host string `json:"host"`
	Port string `json:"port"`
}

type clientApp struct {
	window fyne.Window

	hostEntry        *widget.Entry
	portEntry        *widget.Entry
	secretEntry      *widget.Entry
	console          *widget.TextGrid
	consoleScroll    *container.Scroll
	autoScroll       *widget.Check
	commandEntry     *widget.Entry
	sendButton       *widget.Button
	connectButton    *widget.Button
	disconnectButton *widget.Button
	status           *widget.Label

	mu         sync.Mutex
	conn       net.Conn
	session    *protocol.Session
	cancel     context.CancelFunc
	generation uint64
	lines      []string
	commands   bool
}

func main() {
	application := app.NewWithID("io.mcwatch.client")
	window := application.NewWindow("mcwatch")
	window.Resize(fyne.NewSize(900, 600))
	ui := &clientApp{window: window}
	ui.build()
	ui.loadPreferences()
	window.SetCloseIntercept(func() {
		ui.disconnect()
		application.Quit()
	})
	window.ShowAndRun()
}

func (c *clientApp) build() {
	c.hostEntry = widget.NewEntry()
	c.hostEntry.SetPlaceHolder("Server IP or hostname")
	c.portEntry = widget.NewEntry()
	c.portEntry.SetPlaceHolder("9000")
	c.portEntry.SetText("9000")
	c.secretEntry = widget.NewPasswordEntry()
	c.secretEntry.SetPlaceHolder("Shared secret")

	c.console = widget.NewTextGrid()
	c.consoleScroll = container.NewScroll(c.console)
	c.autoScroll = widget.NewCheck("Auto-scroll", nil)
	c.autoScroll.SetChecked(true)
	c.status = widget.NewLabel("Disconnected")

	c.commandEntry = widget.NewEntry()
	c.commandEntry.SetPlaceHolder("Minecraft console command")
	c.commandEntry.Disable()
	c.sendButton = widget.NewButton("Send", c.sendCommand)
	c.sendButton.Disable()
	c.commandEntry.OnSubmitted = func(string) { c.sendCommand() }

	c.connectButton = widget.NewButton("Connect", c.connect)
	c.disconnectButton = widget.NewButton("Disconnect", c.disconnect)
	c.disconnectButton.Disable()
	testButton := widget.NewButton("Test port", c.testPort)
	saveButton := widget.NewButton("Save log", c.saveLog)
	clearButton := widget.NewButton("Clear", c.clearConsole)

	connection := container.NewGridWithColumns(2,
		widget.NewForm(widget.NewFormItem("Server host/IP", c.hostEntry), widget.NewFormItem("Port", c.portEntry)),
		widget.NewForm(widget.NewFormItem("Shared secret", c.secretEntry)),
	)
	buttons := container.NewHBox(c.connectButton, c.disconnectButton, testButton, saveButton, clearButton)
	consoleHeader := container.NewBorder(nil, nil, nil, c.autoScroll, widget.NewLabel("PaperMC console"))
	commandRow := container.NewBorder(nil, nil, nil, c.sendButton, c.commandEntry)
	content := container.NewBorder(
		container.NewVBox(connection, buttons, consoleHeader),
		container.NewVBox(commandRow, c.status),
		nil, nil,
		c.consoleScroll,
	)
	c.window.SetContent(content)
}

func (c *clientApp) connect() {
	host := strings.TrimSpace(c.hostEntry.Text)
	port := strings.TrimSpace(c.portEntry.Text)
	secret := c.secretEntry.Text
	if host == "" {
		c.status.SetText("Enter the server host or IP")
		return
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		c.status.SetText("Port must be between 1 and 65535")
		return
	}
	c.savePreferences()
	c.mu.Lock()
	c.generation++
	generation := c.generation
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.commands = false
	c.mu.Unlock()
	c.setConnectionUI(generation, "Connecting", false)
	go c.connectWorker(ctx, generation, host, portNumber, secret)
}

func (c *clientApp) connectWorker(ctx context.Context, generation uint64, host string, port int, secret string) {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		c.setConnectionUI(generation, "Disconnected: "+plainNetworkError(err), false)
		return
	}
	c.mu.Lock()
	if c.generation != generation {
		c.mu.Unlock()
		if closeErr := conn.Close(); closeErr != nil {
			c.appendConsole(generation, "[close connection: "+closeErr.Error()+"]")
		}
		return
	}
	c.conn = conn
	c.mu.Unlock()
	session, err := protocol.ClientHandshake(conn, secret)
	if err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			c.appendConsole(generation, "[close connection: "+closeErr.Error()+"]")
		}
		c.mu.Lock()
		if c.generation == generation {
			c.conn = nil
		}
		c.mu.Unlock()
		state := "Wrong secret"
		if ctx.Err() != nil {
			state = "Disconnected"
		}
		c.setConnectionUI(generation, state, false)
		return
	}
	c.mu.Lock()
	if c.generation != generation {
		c.mu.Unlock()
		if closeErr := session.Close(); closeErr != nil {
			c.appendConsole(generation, "[close session: "+closeErr.Error()+"]")
		}
		return
	}
	c.session = session
	c.mu.Unlock()
	c.setConnectionUI(generation, "Connected", false)
	finalState := c.receiveLoop(ctx, generation, session)
	if closeErr := session.Close(); closeErr != nil {
		c.appendConsole(generation, "[close session: "+closeErr.Error()+"]")
	}
	c.mu.Lock()
	if c.generation == generation {
		c.conn, c.session = nil, nil
	}
	c.mu.Unlock()
	c.setConnectionUI(generation, finalState, false)
}

func (c *clientApp) receiveLoop(ctx context.Context, generation uint64, session *protocol.Session) string {
	for {
		if err := session.SetReadDeadline(time.Now().Add(protocol.HeartbeatTTL)); err != nil {
			return "Disconnected: " + plainNetworkError(err)
		}
		message, err := session.Receive()
		if err != nil {
			if ctx.Err() == nil {
				c.appendConsole(generation, "[connection lost: "+plainNetworkError(err)+"]")
				return "Disconnected: connection lost"
			}
			return "Disconnected"
		}
		switch message.Type {
		case protocol.TypeLogLine:
			c.appendConsole(generation, string(message.Payload))
		case protocol.TypeStatus:
			status, err := protocol.DecodeJSON[protocol.Status](message)
			if err == nil {
				c.updateStatus(generation, status)
			}
		case protocol.TypeCapabilities:
			capabilities, err := protocol.DecodeJSON[protocol.Status](message)
			if err == nil {
				c.mu.Lock()
				if c.generation == generation {
					c.commands = capabilities.CommandsAllowed
				}
				c.mu.Unlock()
				c.updateCommandControls(generation)
			}
		case protocol.TypeServerFull:
			c.setConnectionUI(generation, "Server full", false)
			return "Server full"
		case protocol.TypeKick:
			c.appendConsole(generation, "[disconnected by server operator]")
			return "Disconnected"
		case protocol.TypeCommandResponse:
			response, err := protocol.DecodeJSON[protocol.CommandResponse](message)
			if err == nil {
				c.appendConsole(generation, "[server] "+response.Text)
			}
		case protocol.TypePing:
			if string(message.Payload) != "ping" {
				return "Disconnected"
			}
			if err := session.Send(protocol.TypePing, []byte("pong")); err != nil {
				return "Disconnected: connection lost"
			}
		default:
			c.appendConsole(generation, "[server sent an unknown message]")
			return "Disconnected"
		}
	}
}

func (c *clientApp) sendCommand() {
	command := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(c.commandEntry.Text, "\r", ""), "\n", ""))
	if command == "" {
		return
	}
	if len(command) > 256 {
		c.status.SetText("Command is too long (maximum 256 characters)")
		return
	}
	c.mu.Lock()
	session, allowed := c.session, c.commands
	c.mu.Unlock()
	if session == nil || !allowed {
		return
	}
	c.commandEntry.SetText("")
	go func() {
		if err := session.Send(protocol.TypeCommand, []byte(command)); err != nil {
			c.appendConsole(0, "[send failed: "+plainNetworkError(err)+"]")
		}
	}()
}

func (c *clientApp) disconnect() {
	c.mu.Lock()
	c.generation++
	cancel, conn := c.cancel, c.conn
	c.cancel, c.conn, c.session = nil, nil, nil
	c.commands = false
	generation := c.generation
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if conn != nil {
		if err := conn.Close(); err != nil {
			c.appendConsole(generation, "[close connection: "+err.Error()+"]")
		}
	}
	c.setConnectionUI(generation, "Disconnected", false)
}

func (c *clientApp) testPort() {
	host := strings.TrimSpace(c.hostEntry.Text)
	port, err := strconv.Atoi(strings.TrimSpace(c.portEntry.Text))
	if host == "" || err != nil || port < 1 || port > 65535 {
		c.status.SetText("Enter a valid server host and port")
		return
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	go func() {
		conn, err := net.DialTimeout("tcp", address, 5*time.Second)
		if err == nil {
			if closeErr := conn.Close(); closeErr != nil {
				fyne.Do(func() {
					dialog.ShowInformation("Port test", "Port open, but closing the test connection failed: "+closeErr.Error(), c.window)
				})
				return
			}
			fyne.Do(func() { dialog.ShowInformation("Port test", "Port open", c.window) })
			return
		}
		fyne.Do(func() {
			dialog.ShowInformation("Port test", "Port closed/filtered. Check the server, firewall, router forwarding, and public IP.", c.window)
		})
	}()
}

func (c *clientApp) saveLog() {
	content := strings.Join(c.lines, "\n")
	if len(c.lines) > 0 {
		content += "\n"
	}
	save := dialog.NewFileSave(func(file fyne.URIWriteCloser, err error) {
		if err != nil {
			dialog.ShowError(err, c.window)
			return
		}
		if file == nil {
			return
		}
		_, writeErr := io.WriteString(file, content)
		closeErr := file.Close()
		if writeErr != nil {
			dialog.ShowError(writeErr, c.window)
		} else if closeErr != nil {
			dialog.ShowError(closeErr, c.window)
		}
	}, c.window)
	save.SetFileName("mcwatch-console.log")
	save.Show()
}

func (c *clientApp) clearConsole() {
	c.lines = nil
	c.console.SetText("")
}

func (c *clientApp) appendConsole(generation uint64, line string) {
	fyne.Do(func() {
		c.mu.Lock()
		if generation != 0 && c.generation != generation {
			c.mu.Unlock()
			return
		}
		c.lines = append(c.lines, line)
		if len(c.lines) > maxConsoleLines {
			c.lines = append([]string(nil), c.lines[len(c.lines)-maxConsoleLines:]...)
		}
		text := strings.Join(c.lines, "\n")
		c.mu.Unlock()
		c.console.SetText(text)
		if c.autoScroll.Checked {
			c.consoleScroll.ScrollToBottom()
		}
	})
}

func (c *clientApp) updateStatus(generation uint64, status protocol.Status) {
	uptime := time.Duration(status.UptimeSeconds) * time.Second
	fyne.Do(func() {
		c.mu.Lock()
		if c.generation != generation {
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()
		c.status.SetText(fmt.Sprintf("Connected | Minecraft: %s | uptime: %s", status.State, uptime))
	})
}

func (c *clientApp) updateCommandControls(generation uint64) {
	fyne.Do(func() {
		c.mu.Lock()
		enabled := c.generation == generation && c.session != nil && c.commands
		c.mu.Unlock()
		if enabled {
			c.commandEntry.Enable()
			c.sendButton.Enable()
		} else {
			c.commandEntry.Disable()
			c.sendButton.Disable()
		}
	})
}

func (c *clientApp) setConnectionUI(generation uint64, text string, connected bool) {
	fyne.Do(func() {
		c.mu.Lock()
		valid := generation == c.generation
		c.mu.Unlock()
		if !valid {
			return
		}
		c.status.SetText(text)
		if connected || text == "Connected" {
			c.connectButton.Disable()
			c.disconnectButton.Enable()
		} else if text == "Connecting" {
			c.connectButton.Disable()
			c.disconnectButton.Enable()
		} else {
			c.connectButton.Enable()
			c.disconnectButton.Disable()
		}
		if !connected {
			c.commandEntry.Disable()
			c.sendButton.Disable()
		}
	})
}

func (c *clientApp) savePreferences() {
	host, port := c.hostEntry.Text, c.portEntry.Text
	data, err := json.Marshal(preferences{Host: host, Port: port})
	if err != nil {
		dialog.ShowError(err, c.window)
		return
	}
	path, err := preferencesPath()
	if err != nil {
		dialog.ShowError(err, c.window)
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		dialog.ShowError(err, c.window)
		return
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		fyne.Do(func() { dialog.ShowError(err, c.window) })
	}
}

func (c *clientApp) loadPreferences() {
	path, err := preferencesPath()
	if err != nil {
		dialog.ShowError(err, c.window)
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			dialog.ShowError(err, c.window)
		}
		return
	}
	var saved preferences
	if err := json.Unmarshal(data, &saved); err != nil {
		dialog.ShowError(err, c.window)
		return
	}
	c.hostEntry.SetText(saved.Host)
	c.portEntry.SetText(saved.Port)
}

func preferencesPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find user config directory: %w", err)
	}
	return filepath.Join(dir, "mcwatch", "client.json"), nil
}

func plainNetworkError(err error) string {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "connection timed out"
	}
	if errors.Is(err, protocol.ErrAuthentication) {
		return "wrong secret"
	}
	return err.Error()
}
