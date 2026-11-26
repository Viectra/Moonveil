# Architecture — Moonveil (`mvl`)

Moonveil is a bilingual (English / French) clickable terminal network scanner, subnet radar, and port inspector for Linux, authored by **Viectra**.
Built in Rust (2021 edition) on `tokio` (async networking), `ratatui` + `crossterm` (TrueColor TUI & SSH-resilient mouse input), `serde` / `toml` (configuration & known hosts), and `libc` (native Linux system calls).

## Source Tree (1 line = 1 file)

- `Cargo.toml` — Crate manifest (`moonveil` v0.1.0), dependencies, and `moonveil` / `mvl` binary targets.
- `Makefile` — Build, test, lint (`fmt --check` + `clippy`), static musl release, and install automation.
- `README.md` — User documentation covering features, Linux/Tailscale installation, CLI options (`--lang`), and controls.
- `ARCHITECTURE.md` — Concise structural map of modules, runtime data flow, and build targets.
- `.gitignore` — Git exclusions (`/target`, editor swap files, backup artifacts).
- `LICENSE` — MIT License (Copyright © 2026 Viectra).
- `scripts/install.sh` — Release build and `/usr/local/bin/{moonveil,mvl}` installer with optional `--caps` raw ICMP setup.
- `scripts/uninstall.sh` — Removes `/usr/local/bin/moonveil` and `/usr/local/bin/mvl`.
- `src/main.rs` — Entrypoint for `moonveil`, invoking `moonveil::cli::run_cli()` inside `#[tokio::main]`.
- `src/bin/mvl.rs` — Alias binary entrypoint `mvl` delegating to `moonveil::cli::run_cli()`.
- `src/lib.rs` — Library crate root exporting `app`, `cli`, `config`, `net`, and `ui`.
- `src/cli/mod.rs` — CLI root: shared imports, POSIX signal flags (`SHUTDOWN_REQUESTED`, `RESIZE_REQUESTED`), and re-exports.
- `src/cli/args.rs` — CLI argument parser (`--demo`, `--iface`, `--preset`, `--ports`, `--theme`, `--accent`, `--lang`, `--export`) and help text.
- `src/cli/tty.rs` — Terminal RAII lifecycle (`TerminalGuard`), panic cleanup hook, POSIX signal handlers, and `poll_tty`.
- `src/cli/input.rs` — Incremental UTF-8, CSI/SS3 keyboard, and SGR/X10 mouse parser (`AnsiInputParser`) resilient over SSH links.
- `src/cli/runner.rs` — One-shot `--export` runner and main non-blocking interactive event loop.
- `src/config/mod.rs` — Visual themes (`ThemeId`), accents (`AccentId`), language switcher (`Language`), and atomic TOML write helpers.
- `src/config/persistence.rs` — User preferences (`Config`), XDG config/export path resolution, and `config.toml` persistence.
- `src/config/known_hosts.rs` — Named/trusted device store (`KnownHostEntry`, `KnownHostStore`) persisted to `known_hosts.toml`.
- `src/app/mod.rs` — Top-level application state (`App`, 3-view `Tab`, `Modal`) and controller submodules.
- `src/app/state.rs` — `App::new` setup, host filtering/sorting accessors, language helper, persistence helpers, and `on_tick`.
- `src/app/hosts.rs` — Initial host seeding (local/ARP/Tailscale), known-host hydration, and `/proc/net` socket correlation.
- `src/app/network.rs` — Async subnet/deep scan orchestration, continuous ping, interface switching, `EngineEvent` handling, and exports.
- `src/app/input.rs` — Keyboard shortcuts, search bar editing, modal keystrokes, wheel scroll, and selection movement.
- `src/app/actions.rs` — `ClickAction` dispatcher handling language/theme/preset changes, trust stars, rename modals, clipboard, and WoL.
- `src/net/mod.rs` — Network subsystem facade exporting `demo`, `linux`, `model`, `oui`, `scanner`, and `tools`.
- `src/net/model/mod.rs` — Domain model root and formatting utilities (`format_mac`, `format_oui`, `parse_mac`, `format_bps`, `format_bytes`).
- `src/net/model/types.rs` — Core data types (`PortInfo`, `PortState`, `PortFilter`, `DeviceRole`, `NetworkInterface`, `LocalSocket`, `NetworkSnapshot`).
- `src/net/model/host.rs` — `Host` struct, localized `display_name_for`, hostname cleaner, vendor brand shortener, and search query parser.
- `src/net/model/ports.rs` — `ScanMode`, `ScanPreset`, port expression parser, port catalogs (`QUICK_PORTS`, `WEB_DEV_PORTS`, etc.), and `service_info`.
- `src/net/model/inference.rs` — Passive TTL OS guessing, device role inference, and snapshot host statistics.
- `src/net/linux/mod.rs` — Native Linux telemetry module exports.
- `src/net/linux/system.rs` — Privilege detection (`ROOT`/`CAP_NET_RAW`/`USER`), timestamps, `/etc/hosts`, DNS resolvers, and route gateways.
- `src/net/linux/interfaces.rs` — `getifaddrs`, `/sys/class/net`, `/proc/net/dev` collection and CIDR netmask math.
- `src/net/linux/proc_net.rs` — `/proc/net/arp`, `/proc/net/{tcp,tcp6,udp,udp6}`, inode-to-PID mapping, and Tailscale peer discovery.
- `src/net/scanner/mod.rs` — Async scanner config (`ScanConfig`), streamed `EngineEvent`, and skeleton host builders.
- `src/net/scanner/engine.rs` — CIDR target slicing (including Tailscale `/32` peers) and concurrent per-host async port scanning.
- `src/net/scanner/probes.rs` — Retrying TCP connect port probes, SSH/HTTP/TLS banner grabber, and local socket `InUse` correlation.
- `src/net/scanner/discovery.rs` — ICMP raw ping + TCP touch liveness probing and multi-protocol PTR/mDNS/NetBIOS hostname resolution.
- `src/net/oui.rs` — Offline IEEE MAC vendor resolution (`/usr/share/ieee-data/oui.csv` + embedded map) and LAA randomized MAC detection.
- `src/net/tools.rs` — Continuous ping utility, UDP `IP_RECVERR` traceroute, Wake-on-LAN packet sender, OSC 52 copy, and snapshot exporters.
- `src/net/demo/mod.rs` — Deterministic multi-interface dataset builder (`build_demo_snapshot`) for `--demo` and tests.
- `src/net/demo/data.rs` — Demo interfaces, local sockets, timeline events, and host/port fixture helpers.
- `src/net/demo/hosts.rs` — Simulated LAN, Docker, and Tailscale host inventories.
- `src/net/demo/simulation.rs` — Animated RTT/throughput demo tick loop and synthetic traceroute generation.
- `src/ui/mod.rs` — Root Ratatui renderer dispatching splash, sidebar/topbar/footer shell, 3 active views, toasts, and modals.
- `src/ui/layout.rs` — Left sidebar with Moonveil emblem, interface/scan/preset topbar, Crescent Scan Wave bar, and status footer.
- `src/ui/splash.rs` — Animated launch logo screen and minimum-size terminal guard overlay.
- `src/ui/modals.rs` — Centered localized overlays for controls help, host renaming, and custom port ranges.
- `src/ui/hit.rs` — Per-frame clickable region (`ClickAction`) and mouse-wheel scroll (`ScrollTarget`) registry.
- `src/ui/theme.rs` — TrueColor surface palettes (`Moonveil`, `Obsidian`, `Abyss`, `Graphite`, `Terminal`), accents, and Unicode truncation.
- `src/ui/widgets/mod.rs` — Custom Ratatui widget exports (`emblem`, `SplineChart`, gauges).
- `src/ui/widgets/logo.rs` — Half-block Moonveil crescent-and-veil pixel matrices with sweep shimmer.
- `src/ui/widgets/charts.rs` — Smooth 24-bit subpixel cosine-interpolated spline chart (`SplineChart`).
- `src/ui/widgets/primitives.rs` — RGB color interpolation (`mix`), Crescent Scan Wave, and segmented port ratio bar.
- `src/ui/hosts/mod.rs` — Hosts view responsive split layout (`toolbar`, `table`, `inspector`).
- `src/ui/hosts/toolbar.rs` — Clickable smart search input and online host counters.
- `src/ui/hosts/table.rs` — Click-sortable host list displaying device names, IPv4, RTT latency, and open ports.
- `src/ui/hosts/inspector.rs` — Detailed device card: trust star, copyable IP/MAC, RTT spline, filterable/collapsible ports, and actions.
- `src/ui/radar.rs` — Interactive `16×16` `.0`–`.255` subnet grid with `/24` pagination and selected-address jump.
- `src/ui/settings/mod.rs` — Settings view two-column layout and shared label helpers.
- `src/ui/settings/scan_options.rs` — Port preset selector, custom port modal trigger, concurrency/timeout controls, toggles, and JSON/CSV/MD export.
- `src/ui/settings/theme_studio.rs` — Bilingual language switcher (`English` / `Français`), theme palette, accent swatches, and motion toggles.
- `tests/engine_tests.rs` — Unit/integration tests for port parsing, OUI lookup, hostname naming (`En`/`Fr`), Linux helpers, and live loopback scans.
- `tests/cli_and_export_tests.rs` — Tests for JSON/CSV/Markdown snapshot exports, `Config`/`KnownHostStore` TOML roundtrips, and `AnsiInputParser`.
- `tests/ui_render_tests.rs` — Headless `TestBackend` UI render tests across English/French, window sizes, mouse clicks, and XDG persistence.

## Entrypoints & Main Data Flow

1. `moonveil` / `mvl` parse CLI arguments (`src/cli/args.rs`), load `Config` (`src/config/persistence.rs`), and either run `--export` headlessly or initialize `TerminalGuard` + `App` (`src/cli/runner.rs`).
2. Startup seeds local/ARP/Tailscale hosts (`src/app/hosts.rs`) and starts an async `run_scan` task (`src/net/scanner/engine.rs`) streaming `EngineEvent` updates back to `App::on_tick`.
3. Every UI draw (`src/ui/mod.rs`) records interactive `ClickAction` and `ScrollTarget` bounds in `HitRegistry`, routing mouse clicks over SSH/local PTYs and keyboard shortcuts cleanly through `App::handle_mouse` and `App::handle_key`.
