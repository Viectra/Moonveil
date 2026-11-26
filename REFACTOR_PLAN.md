# Plan de Refactorisation — Moonveil

- [x] `src/ui/settings.rs` (438 lignes) → découpage proposé en sous-modules (`src/ui/settings/mod.rs`, `scan_options.rs`, `theme_studio.rs`)
- [x] `src/ui/widgets.rs` (450 lignes) → découpage proposé en sous-modules (`src/ui/widgets/mod.rs`, `logo.rs`, `charts.rs`, `primitives.rs`)
- [x] `src/config.rs` (447 lignes) → découpage proposé en sous-modules (`src/config/mod.rs`, `persistence.rs`, `known_hosts.rs`)
- [x] `tests/ui_and_engine.rs` (550 lignes) → découpage proposé en suites ciblées (`tests/engine_tests.rs`, `tests/cli_and_export_tests.rs`, `tests/ui_render_tests.rs`)
- [x] `src/net/demo.rs` (914 lignes) → découpage proposé en sous-modules (`src/net/demo/mod.rs`, `data.rs` / données statiques simulées, `simulation.rs`)
- [x] `src/net/linux.rs` (634 lignes) → découpage proposé en sous-modules (`src/net/linux/mod.rs`, `proc_net.rs`, `interfaces.rs`, `system.rs`)
- [x] `src/ui/mod.rs` (750 lignes) → découpage proposé en sous-modules (`src/ui/mod.rs`, `layout.rs`, `splash.rs`, `modals.rs`)
- [x] `src/ui/hosts.rs` (964 lignes) → découpage proposé en sous-modules (`src/ui/hosts/mod.rs`, `toolbar.rs`, `table.rs`, `inspector.rs`)
- [x] `src/cli.rs` (1044 lignes) → découpage proposé en sous-modules (`src/cli/mod.rs`, `args.rs`, `tty.rs`, `runner.rs`)
- [x] `src/net/model.rs` (1058 lignes) → découpage proposé en sous-modules (`src/net/model/mod.rs`, `types.rs`, `ports.rs`, `inference.rs`)
- [x] `src/net/scanner.rs` (1198 lignes) → découpage proposé en sous-modules (`src/net/scanner/mod.rs`, `engine.rs`, `probes.rs`)
- [x] `src/app.rs` (1734 lignes) → découpage proposé en sous-modules (`src/app/mod.rs`, `state.rs`, `input.rs`, `network.rs`)
