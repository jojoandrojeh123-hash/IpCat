//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/term"
	"mcwatch/internal/protocol"
	mcserver "mcwatch/internal/server"
)

type config struct {
	Bind           string `json:"bind"`
	Port           int    `json:"port"`
	MCDir          string `json:"mc_dir"`
	Jar            string `json:"jar"`
	Java           string `json:"java"`
	XMS            string `json:"xms"`
	XMX            string `json:"xmx"`
	RestartOnCrash bool   `json:"restart_on_crash"`
	AllowCommands  bool   `json:"allow_commands"`
	SecretFile     string `json:"secret_file"`
}

func defaults() config {
	return config{Bind: "0.0.0.0", Port: 9000, MCDir: ".", Jar: "paper.jar", Java: "java", XMS: "1G", XMX: "2G"}
}

func main() {
	cfg, err := parseConfig(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	secret, err := loadSecret(cfg.SecretFile)
	if err != nil {
		log.Fatal(err)
	}
	if len(secret) < 12 {
		log.Print("WARNING: shared secret is shorter than 12 characters; use a long random secret")
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		log.Fatal("--port must be between 1 and 65535")
	}
	if strings.TrimSpace(cfg.XMS) == "" || strings.TrimSpace(cfg.XMX) == "" {
		log.Fatal("--xms and --xmx must not be empty")
	}

	listener, err := net.Listen("tcp", net.JoinHostPort(cfg.Bind, strconv.Itoa(cfg.Port)))
	if err != nil {
		log.Fatalf("listen control port: %v", err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	remoteCommands := make(chan string, 64)
	var paperAvailable atomic.Bool
	control := mcserver.NewControlServer(secret, cfg.AllowCommands, func(_ uint64, command string) error {
		if !paperAvailable.Load() {
			return errors.New("PaperMC is not running")
		}
		select {
		case remoteCommands <- command:
			return nil
		default:
			return errors.New("PaperMC command queue is full")
		}
	}, func(format string, args ...any) {
		log.Printf(format, args...)
	})
	control.SetStatus(protocol.Status{State: "starting"})
	controlDone := make(chan error, 1)
	go func() {
		err := control.Serve(ctx, listener)
		controlDone <- err
		if err != nil {
			cancel()
		}
	}()
	log.Printf("control server listening on %s", listener.Addr())

	terminalLines := make(chan string)
	go readTerminal(ctx, terminalLines)
	lineWriter := &consoleLineWriter{onLine: func(line string) {
		control.PublishLine(line)
		if strings.Contains(line, "Done (") {
			paperAvailable.Store(true)
			control.SetStatus(protocol.Status{State: "running"})
		}
	}}
	err = supervise(ctx, cfg, control, lineWriter, terminalLines, remoteCommands, &paperAvailable)
	cancel()
	if controlErr := <-controlDone; controlErr != nil && err == nil {
		err = controlErr
	}
	if err != nil {
		log.Fatal(err)
	}
}

func parseConfig(args []string) (config, error) {
	cfg := defaults()
	flags := flag.NewFlagSet("mcwatch-server", flag.ContinueOnError)
	configPath := flags.String("config", "config.json", "JSON config file")
	bind := flags.String("bind", cfg.Bind, "control address to bind")
	port := flags.Int("port", cfg.Port, "control port")
	mcDir := flags.String("mc-dir", cfg.MCDir, "PaperMC directory")
	jar := flags.String("jar", cfg.Jar, "PaperMC jar file")
	java := flags.String("java", cfg.Java, "Java executable")
	xms := flags.String("xms", cfg.XMS, "initial JVM heap size")
	xmx := flags.String("xmx", cfg.XMX, "maximum JVM heap size")
	restart := flags.Bool("restart-on-crash", cfg.RestartOnCrash, "restart PaperMC after a crash")
	allow := flags.Bool("allow-commands", cfg.AllowCommands, "allow authenticated clients to send console commands")
	secretFile := flags.String("secret-file", "", "0600 file containing the shared secret")
	if err := flags.Parse(args); err != nil {
		return cfg, err
	}

	configSpecified := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "config" {
			configSpecified = true
		}
	})
	data, err := os.ReadFile(*configPath)
	if err != nil && !(errors.Is(err, os.ErrNotExist) && !configSpecified) {
		return cfg, fmt.Errorf("read config %q: %w", *configPath, err)
	}
	if err == nil {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("parse config %q: %w", *configPath, err)
		}
	}

	flags.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "bind":
			cfg.Bind = *bind
		case "port":
			cfg.Port = *port
		case "mc-dir":
			cfg.MCDir = *mcDir
		case "jar":
			cfg.Jar = *jar
		case "java":
			cfg.Java = *java
		case "xms":
			cfg.XMS = *xms
		case "xmx":
			cfg.XMX = *xmx
		case "restart-on-crash":
			cfg.RestartOnCrash = *restart
		case "allow-commands":
			cfg.AllowCommands = *allow
		case "secret-file":
			cfg.SecretFile = *secretFile
		}
	})
	return cfg, nil
}

func loadSecret(path string) (string, error) {
	if secret := os.Getenv("MCWATCH_SECRET"); secret != "" {
		return strings.TrimRight(secret, "\r\n"), nil
	}
	if path != "" {
		info, err := os.Stat(path)
		if err != nil {
			return "", fmt.Errorf("stat secret file: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return "", fmt.Errorf("secret file %q must be a regular file with permissions 0600", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read secret file: %w", err)
		}
		secret := strings.TrimRight(string(data), "\r\n")
		if secret == "" {
			return "", errors.New("secret file is empty")
		}
		return secret, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("set MCWATCH_SECRET, use --secret-file, or run interactively to enter the shared secret")
	}
	fmt.Fprint(os.Stderr, "Shared secret: ")
	data, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read shared secret: %w", err)
	}
	if len(data) == 0 {
		return "", errors.New("shared secret must not be empty")
	}
	return string(data), nil
}

func supervise(ctx context.Context, cfg config, control *mcserver.ControlServer, writer *consoleLineWriter, terminal <-chan string, remote <-chan string, available *atomic.Bool) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var runningSince time.Time

	for {
		cmd, stdin, wait, err := startPaper(cfg, writer)
		if err != nil {
			control.SetStatus(protocol.Status{State: "crashed"})
			return err
		}
		available.Store(false)
		control.SetStatus(protocol.Status{State: "starting"})
		log.Printf("started PaperMC process pid=%d", cmd.Process.Pid)

		restart := false
		quit := false
		for !restart && !quit {
			select {
			case line := <-terminal:
				switch {
				case line == "!quit":
					quit = true
				case strings.HasPrefix(line, "!"):
					handleAdminCommand(line, control)
				default:
					if err := writeConsole(stdin, line); err != nil {
						log.Printf("write PaperMC stdin: %v", err)
					}
				}
			case command := <-remote:
				if err := writeConsole(stdin, command); err != nil {
					log.Printf("write remote command to PaperMC: %v", err)
				}
			case <-ticker.C:
				if !runningSince.IsZero() {
					control.SetStatus(protocol.Status{State: "running", UptimeSeconds: int64(time.Since(runningSince).Seconds())})
				}
			case err := <-wait:
				available.Store(false)
				writer.Flush()
				if err != nil {
					control.SetStatus(protocol.Status{State: "crashed"})
					log.Printf("PaperMC exited with error: %v", err)
					if !eulaAccepted(cfg.MCDir) {
						log.Print("PaperMC did not start because eula.txt is not accepted. Review the Minecraft EULA and set eula=true yourself; mcwatch never edits eula.txt.")
					} else if cfg.RestartOnCrash {
						restart = true
					}
				} else {
					control.SetStatus(protocol.Status{State: "stopped"})
					log.Print("PaperMC stopped")
				}
				if restart {
					break
				}
				return waitForExit(ctx, control, terminal)
			case <-ctx.Done():
				available.Store(false)
				err := gracefulStop(cmd, stdin, wait)
				control.SetStatus(protocol.Status{State: "stopped"})
				return err
			}
			if quit {
				available.Store(false)
				err := gracefulStop(cmd, stdin, wait)
				control.SetStatus(protocol.Status{State: "stopped"})
				return err
			}
			if control.CurrentStatus().State == "running" && runningSince.IsZero() {
				runningSince = time.Now()
			}
		}
		if restart {
			runningSince = time.Time{}
			log.Print("restarting PaperMC in 3 seconds")
			timer := time.NewTimer(3 * time.Second)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return nil
			}
		}
	}
}

func startPaper(cfg config, output io.Writer) (*exec.Cmd, io.WriteCloser, <-chan error, error) {
	mcDir, err := filepath.Abs(cfg.MCDir)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("resolve --mc-dir: %w", err)
	}
	jar := cfg.Jar
	if filepath.IsAbs(jar) {
		jar, err = filepath.Rel(mcDir, jar)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("resolve PaperMC jar: %w", err)
		}
	}
	cmd := exec.Command(cfg.Java, "-Xms"+cfg.XMS, "-Xmx"+cfg.XMX, "-jar", jar, "--nogui")
	cmd.Dir = mcDir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = output
	cmd.Stderr = output
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open PaperMC stdin: %w", err)
	}
	if err := cmd.Start(); err != nil {
		if closeErr := stdin.Close(); closeErr != nil {
			log.Printf("close PaperMC stdin after start failure: %v", closeErr)
		}
		return nil, nil, nil, fmt.Errorf("start PaperMC: %w", err)
	}
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	return cmd, stdin, wait, nil
}

func gracefulStop(cmd *exec.Cmd, stdin io.WriteCloser, wait <-chan error) error {
	log.Print("stopping PaperMC gracefully")
	if err := writeConsole(stdin, "stop"); err != nil {
		log.Printf("send stop to PaperMC: %v", err)
	}
	timer := time.NewTimer(60 * time.Second)
	defer timer.Stop()
	select {
	case err := <-wait:
		if err != nil {
			log.Printf("PaperMC exited while stopping: %v", err)
		}
		return nil
	case <-timer.C:
		log.Print("PaperMC did not stop within 60 seconds; killing it")
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return fmt.Errorf("kill PaperMC: %w", err)
		}
		if err := <-wait; err != nil {
			log.Printf("PaperMC killed: %v", err)
		}
		return nil
	}
}

func writeConsole(stdin io.Writer, line string) error {
	_, err := io.WriteString(stdin, line+"\n")
	return err
}

func handleAdminCommand(line string, control *mcserver.ControlServer) {
	fields := strings.Fields(line)
	switch {
	case line == "!list":
		clients := control.Clients()
		log.Printf("connected clients (%d/%d):", len(clients), mcserver.MaxClients)
		for _, client := range clients {
			log.Printf("  %d %s", client.ID, client.Remote)
		}
	case line == "!status":
		status := control.CurrentStatus()
		log.Printf("PaperMC state=%s uptime=%s clients=%d/%d", status.State, time.Duration(status.UptimeSeconds)*time.Second, control.ClientCount(), mcserver.MaxClients)
	case len(fields) == 2 && fields[0] == "!kick":
		id, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || !control.Kick(id) {
			log.Printf("no connected client with id %q", fields[1])
		} else {
			log.Printf("kicked client %d", id)
		}
	case line == "!quit":
	default:
		log.Print("terminal commands: !list, !kick <id>, !status, !quit")
	}
}

func waitForExit(ctx context.Context, control *mcserver.ControlServer, terminal <-chan string) error {
	for {
		select {
		case line := <-terminal:
			if line == "!quit" {
				return nil
			}
			if strings.HasPrefix(line, "!") {
				handleAdminCommand(line, control)
			} else {
				log.Print("PaperMC is not running; terminal input was not sent")
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func readTerminal(ctx context.Context, lines chan<- string) {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		select {
		case lines <- scanner.Text():
		case <-ctx.Done():
			return
		}
	}
	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		log.Printf("read terminal input: %v", err)
	}
}

func eulaAccepted(mcDir string) bool {
	data, err := os.ReadFile(filepath.Join(mcDir, "eula.txt"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.EqualFold(line, "eula=true") {
			return true
		}
	}
	return false
}

type consoleLineWriter struct {
	mu     sync.Mutex
	buffer []byte
	onLine func(string)
}

func (w *consoleLineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := os.Stdout.Write(p)
	if err != nil {
		return n, err
	}
	w.buffer = append(w.buffer, p[:n]...)
	for {
		i := bytes.IndexByte(w.buffer, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimSuffix(string(w.buffer[:i]), "\r")
		w.onLine(line)
		w.buffer = w.buffer[i+1:]
	}
	if len(w.buffer) > protocol.MaxPlaintext-128 {
		w.onLine(string(w.buffer[:protocol.MaxPlaintext-128]) + " [line truncated]")
		w.buffer = nil
	}
	return n, nil
}

func (w *consoleLineWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buffer) > 0 {
		w.onLine(strings.TrimSuffix(string(w.buffer), "\r"))
		w.buffer = nil
	}
}
