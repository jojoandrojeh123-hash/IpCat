# mcwatch

mcwatch is a small PaperMC supervisor and encrypted console viewer. The Linux
server starts PaperMC and broadcasts its console to up to eight directly
connected clients. The native Fyne client connects to the server's IP and
control port; there is no account, relay, or Tailscale dependency.

## Build

The server is Linux-only and has no GUI or C dependency:

```sh
make server
```

This builds Linux amd64 and arm64 binaries. For a single architecture:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o mcwatch-server ./cmd/server
```

The Fyne client must be built natively on each desktop OS:

```sh
go build -o mcwatch-client ./cmd/client
```

- **Windows:** install MinGW-w64 and ensure `gcc` is on `PATH`. The release
  build uses `go build -ldflags "-H=windowsgui" -o mcwatch-client.exe ./cmd/client`
  to avoid a console window.
- **macOS:** install Xcode command line tools with `xcode-select --install`.
  Unsigned builds may require right-clicking the app/binary and choosing
  **Open** the first time.
- **Linux:** install `gcc libgl1-mesa-dev xorg-dev pkg-config` (for
  Debian/Ubuntu: `sudo apt install gcc libgl1-mesa-dev xorg-dev pkg-config`).

`fyne-cross` with Docker is another cross-build option. For macOS, building on
a Mac or using the included GitHub Actions workflow is the most reliable path.
The workflow builds server amd64/arm64 and native Windows, macOS, and Linux
client artifacts.

## Server

Install Java, place `paper.jar` and the world in a directory, review
Minecraft's EULA, and set `eula=true` yourself in that directory's `eula.txt`.
mcwatch never edits the EULA file.

Create a secret file readable only by the server account:

```sh
install -m 600 /dev/null /etc/mcwatch-secret
printf '%s' 'replace-with-a-long-random-secret' > /etc/mcwatch-secret
```

Start the server:

```sh
./mcwatch-server --mc-dir /srv/minecraft --secret-file /etc/mcwatch-secret
```

The server listens on `0.0.0.0:9000` by default and starts:

```text
java -Xms1G -Xmx2G -jar paper.jar --nogui
```

You can instead set `MCWATCH_SECRET` or omit both secret sources to enter the
secret interactively. Secrets shorter than 12 characters trigger a warning.
Never put the secret on the command line.

Options are also read from `config.json` (or `--config /path/to/config.json`);
explicit flags override the JSON values. Example:

```json
{
  "bind": "0.0.0.0",
  "port": 9000,
  "mc_dir": "/srv/minecraft",
  "jar": "paper.jar",
  "java": "java",
  "xms": "1G",
  "xmx": "2G",
  "restart_on_crash": false,
  "allow_commands": false,
  "secret_file": "/etc/mcwatch-secret"
}
```

Other flags: `--bind`, `--port`, `--mc-dir`, `--jar`, `--java`, `--xms`,
`--xmx`, `--restart-on-crash`, `--allow-commands`, and `--secret-file`.
Authenticated remote Minecraft commands are disabled unless
`--allow-commands` is set; enabled commands are capped at 256 characters and
limited to five per client per 10 seconds.

Type normal lines into the server terminal to send them to PaperMC. Prefix
mcwatch actions with `!`:

- `!list` — list connected clients.
- `!kick <id>` — disconnect a client.
- `!status` — show PaperMC state, uptime, and client count.
- `!quit` — gracefully stop PaperMC and mcwatch.

SIGINT/SIGTERM also sends PaperMC `stop`, waits up to 60 seconds for world
saving, and then kills the process if it has not exited.

For an interactive session, run mcwatch in `tmux` or `screen`. For unattended
hosting, a systemd unit can run it as a non-root account:

```ini
[Unit]
Description=mcwatch PaperMC supervisor
After=network-online.target
Wants=network-online.target

[Service]
User=minecraft
Group=minecraft
WorkingDirectory=/srv/minecraft
ExecStart=/usr/local/bin/mcwatch-server --mc-dir /srv/minecraft --secret-file /etc/mcwatch-secret
Restart=on-failure
RestartSec=5
KillMode=mixed
TimeoutStopSec=70

[Install]
WantedBy=multi-user.target
```

Ensure `/etc/mcwatch-secret` is owned by the `minecraft` user and remains mode
`0600`. Install the unit as `/etc/systemd/system/mcwatch.service`, then run
`sudo systemctl daemon-reload && sudo systemctl enable --now mcwatch`.

## Client

Run `mcwatch-client` (the GUI) and enter the server host/IP, control port
(default `9000`), and the same shared secret. The client remembers only the
host and port in the user's config directory; it never saves the secret.
Use **Test port** to check TCP reachability, **Save log** to export the visible
console, and **Clear** to clear its local display. The client retains at most
5000 lines in memory.

The command box is enabled only when the server advertises command access.
Connection loss leaves the client disconnected; use **Connect** to reconnect.

## Making the server reachable

There are two TCP ports: **9000** is mcwatch's encrypted control port;
**25565** is the Minecraft Java Edition game port used by players. Bedrock
players need Geyser, which is outside this project's scope.

1. On the Linux server, find its local address with `ip a`. Reserve that
   address in your router or configure a static address so it does not change.
2. Add router port-forwarding rules for external TCP `9000` to
   `<server-local-IP>:9000`, and external TCP `25565` to
   `<server-local-IP>:25565`.
3. Open both ports in the host firewall. With UFW:

   ```sh
   sudo ufw allow 9000/tcp
   sudo ufw allow 25565/tcp
   ```

   With firewalld:

   ```sh
   sudo firewall-cmd --permanent --add-port=9000/tcp
   sudo firewall-cmd --permanent --add-port=25565/tcp
   sudo firewall-cmd --reload
   ```

4. If the server is a VPS, skip the router setup and allow TCP `9000` and
   `25565` in the provider's firewall/security group.
5. Find the public IP with `curl ifconfig.me`. Test from outside the home
   network, such as a phone using mobile data; a test from the same Wi-Fi may
   succeed even when router forwarding is wrong.
6. If the router's WAN IP differs from the public IP, the ISP may use CGNAT.
   Port forwarding will not work through CGNAT; use a VPS or request a public
   IP from the ISP.
7. Expose port `9000` only when needed, use a long random secret, and consider
   restricting source IPs in the firewall. The control port grants access to
   live server logs and, when explicitly enabled, Minecraft console commands.

## Tests

```sh
go test -race ./...
go vet ./...
```
