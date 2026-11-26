<p align="center">
  <img src="assets/moonveil-icon.png" alt="Moonveil Logo" width="96" />
</p>

<h1 align="center">Moonveil (<code>mvl</code>)</h1>

<p align="center">
  A fast, clickable, smoothly animated terminal network scanner, subnet radar, and socket inspector for Linux — authored by <strong>Viectra</strong>.
</p>

---

## Highlights

- **Moonveil Visual Identity**: Cosmic navy (`#0D0F22`), electric **MOON** violet (`#9B59F6`), and warm **VEIL** crescent peach (`#F7CDBE`) TrueColor interface featuring a half-block Moonveil emblem, animated launch shimmer, Crescent Scan Wave bar, and smooth 24-bit subpixel spline charts.
- **100% Mouse Clickable + Keyboard Driven**: Click sidebar tabs, interface switchers, Normal/Advanced mode slider, column sort headers, host rows (double-click to inspect), trust stars, port filter pills, collapsible closed-port rows, `16×16` Subnet Radar tiles, and Watch/Export controls.
- **Port Intelligence (`In Use` • `Open` • `Closed` • `Filtered`)**:
  - **In Use**: Correlates `/proc/net/{tcp,tcp6,udp,udp6}` and `/proc/<pid>/fd` to highlight active `ESTABLISHED` connections with owning process name, PID, and peer endpoint.
  - **Open**: Listening services enriched with live HTTP `<title>`, TLS certificate CN/version, and SSH/FTP/Redis/SMTP greeting banners.
  - **Closed vs. Filtered**: Distinguishes explicit TCP `RST` (`Closed`) from firewall silent drops (`Filtered`), collapsing closed ports cleanly into an expandable summary pill.
- **Normal Mode vs. Advanced Mode (`m`)**: Switch instantly without losing scan data:
  - **Normal Mode ("Clean Radar")**: Device role icons, friendly hostname/nickname, IP, IEEE OUI vendor, RTT badge, and plain-English service tags (`SSH`, `Web`, `Files`, `DB`, `Docker`).
  - **Advanced Mode ("Deep Recon")**: Full IPv4 + IPv6, MAC + OUI prefix, ARP neighbor state (`REACHABLE`/`STALE`/`DELAY`), TTL OS guess, per-state port breakdown, raw banners, and custom port expressions (`1-65535`, `22,80,443,8000-8090`).
- **Interactive `16×16` Subnet Radar**: Clickable `.0`–`.255` grid with live scan sweep cursor and `/24` slice paging for `/16` networks (e.g., Docker bridges).
- **Watch Mode, Host Tools & Exports**: Continuous background sweep with change timeline (new/untrusted host alerts, port changes), persistent trusted/bookmarked hosts, live RTT Ping Monitor, unprivileged `IP_RECVERR` Traceroute, Wake-on-LAN (`⏻ WoL`), OSC 52 clipboard copy, and `JSON` / `CSV` / `Markdown` exports.
- **Privilege-Smart Engine**: Works immediately as an unprivileged user (`USER`/`ICMP` via TCP touch, `/proc/net/arp`, mDNS `.local`, and `/proc/net` socket correlation) and unlocks raw ICMP/SYN/ARP probes when run with `sudo` or `CAP_NET_RAW`.

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
| Switch views | Click sidebar / topbar tab | `1`–`5` or `Tab` / `Shift+Tab` |
| Toggle Normal / Advanced | Click `Normal ──● Advanced` | `m` |
| Start / Stop scan | Click `⟳ Scan` / `■ Stop` | `s` |
| Cycle port preset | Click preset pill | `p` |
| Search & smart filter | Click search bar | `/` (`port:22`, `state:in-use`, `state:closed`, `vendor:apple`) |
| Toggle Watch Mode | Click `Watch` pill | `w` |
| Trust / Rename device | Click `★ Trusted` or `✎ Rename` | `t` / `n` |
| Navigate & scroll | Click / Wheel scroll | `↑` `↓` / `j` `k` |
| Export JSON | Click `Export JSON` | `e` |
| Help / Quit | Click `? Help` / `× Quit` | `?` / `q` or `Ctrl+C` |

---

## Branch Workflow

- `develop` — Active development (`update: ...`, `fix: ...`)
- `main` — Verified, stable releases

MIT License — Copyright © 2026 **Viectra**
