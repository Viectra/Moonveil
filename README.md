<p align="center">
  <img src="assets/moonveil-icon.png" alt="Moonveil Logo" width="96" />
</p>

<h1 align="center">Moonveil (<code>mvl</code>)</h1>

<p align="center">
  A fast, clickable, smoothly animated terminal network scanner, subnet radar, and socket inspector for Linux — authored by <strong>Viectra</strong>.
</p>

---

## Highlights

- **Moonveil Visual Identity**: Cosmic navy (`#0D0F22`), electric **MOON** violet (`#9B59F6`), and warm **VEIL** crescent peach (`#F7CDBE`) TrueColor interface featuring a half-block Moonveil emblem, animated launch shimmer, and Crescent Scan Wave bar.
- **100% Mouse Clickable + Keyboard Driven**: Clean 3-view layout (**Devices**, **Subnet Map**, **Settings**) with clickable interface switchers, sortable device table, port filters (`Open`, `In Use`, `Closed`), `16×16` Subnet Map tiles, and snapshot exports.
- **Multi-Protocol Machine Identification**: Automatically resolves device names via router DNS PTR (bypassing `systemd-resolved`), unicast/multicast mDNS (`.local`), NetBIOS (`:137`), LLMNR (`:5355`), `/etc/hosts`, TLS certificate CNs, `tailscale status`, and friendly OUI vendor fallbacks so `Device` never repeats a raw IP.
- **Port Intelligence (`Open` • `In Use` • `Closed` • `Filtered`)**:
  - **In Use**: Correlates `/proc/net/{tcp,tcp6,udp,udp6}` and `/proc/<pid>/fd` to highlight active `ESTABLISHED` local sessions with owning process name, PID, and peer endpoint.
  - **Open**: Enriches listening services with HTTP `<title>`, Server header, TLS certificate CN/version, and SSH/FTP/Redis/SMTP greeting banners across both standard and custom/ephemeral HTTP ports.
  - **Closed vs. Filtered**: Cleanly separates open ports by default from TCP `RST` (`Closed`) and firewall drops (`Filtered`) under the `Closed` tab.
- **Privilege-Smart Engine**: Works immediately as an unprivileged user (`USER`/`ICMP` via TCP touch, `/proc/net/arp`, and `/proc/net` socket correlation) and unlocks raw ICMP/SYN/ARP probes when run with `sudo` or `CAP_NET_RAW`.

---

## Build & Install on Linux

```bash
git clone -b main https://github.com/Viectra/Moonveil.git
cd Moonveil
./scripts/install.sh
```

Optional capability setup for raw ICMP ping without `sudo`:

```bash
./scripts/install.sh --caps
```

Run either `moonveil` or `mvl` (or preview safely with `mvl --demo`).

---

## CLI Options

```text
moonveil [OPTIONS]
mvl [OPTIONS]
```

- `--demo` — Preview UI with realistic simulated LAN, Docker, and Tailscale telemetry
- `-i, --iface <NAME>` — Start on a specific Linux interface (`enp6s18`, `wlan0`, `docker0`, etc.)
- `--normal` / `--advanced` — Start in Normal Mode or Advanced Mode
- `--preset <PRESET>` — `quick`, `standard`, `full`, `webdev`, `custom`
- `--ports <EXPR>` — Custom port expression (`22,80,443,8000-8090`)
- `--watch` — Start with background Watch Mode enabled
- `--theme <THEME>` — `moonveil`, `obsidian`, `abyss`, `graphite`, `terminal`
- `--accent <COLOR>` — `violet`, `peach`, `cyan`, `mint`, `rose`, `amber`
- `--no-splash` — Skip launch emblem animation
- `--export <json|csv|md> <PATH>` — Run a one-shot scan and write a snapshot file directly

---

## Controls

| Action | Mouse | Keyboard |
| --- | --- | --- |
| Switch views | Click sidebar / topbar tab | `1`–`3` or `Tab` / `Shift+Tab` |
| Start / Stop scan | Click `▶ Scan` / `■ Stop` | `s` |
| Cycle port preset | Click `Preset:` pill | `p` |
| Deep scan device (1,000+ ports) | Click `▶ Deep Scan` | — |
| Search & smart filter | Click search bar | `/` (`port:22`, `state:in-use`, `vendor:canon`) |
| Rename device | Click `* Rename` | `n` |
| Navigate & scroll | Click / Wheel scroll | `↑` `↓` / `j` `k` |
| Export JSON / CSV / MD | Click export in `Settings` | `e` (JSON) |
| Help / Quit | Click `? Help` / `× Quit` | `?` / `q` or `Ctrl+C` |

---

## Branch Workflow

- `develop` — Active development (`update: ...`, `fix: ...`)
- `main` — Verified, stable releases

MIT License — Copyright © 2026 **Viectra**
