# Architecture — Moonveil (`mvl`)

Scanner réseau TUI cliquable et animé pour Linux (découverte de sous-réseaux, radar IP, inspection de ports/sockets et mode Watch).
Écrit en Rust (édition 2021) avec `tokio` (async/réseau), `ratatui` + `crossterm` (interface terminal TrueColor & souris), `serde`/`toml` (persistance) et `libc` (appels système Linux).

## Arborescence des fichiers sources (1 ligne = 1 fichier)

- `Cargo.toml` — Manifeste Cargo du crate `moonveil` (`0.1.0`), dépendances (`ratatui`, `crossterm`, `tokio`, `serde`, `toml`, `libc`, `unicode-width`) et définition des binaires `moonveil` et `mvl`.
- `Makefile` — Cibles d'automatisation : build release/musl, tests (`cargo test`), lint (`fmt --check` + `clippy`), lancement `--demo`, installation et nettoyage.
- `README.md` — Documentation utilisateur : présentation des fonctionnalités, installation Linux, options CLI, contrôles clavier/souris et workflow de branches.
- `CLAUDE.md` — Règles impératives de travail Git, de lecture ciblée et d'économie de tokens pour les assistants IA.
- `AI_RULES.md` — Copie identique de `CLAUDE.md` destinée aux autres assistants IA utilisés sur le dépôt.
- `ARCHITECTURE.md` — Cartographie légère du projet, points d'entrée, flux principaux et zones exclues.
- `.gitignore` — Exclusions Git (`/target`, `**/*.rs.bk`, `*.swp`, `.DS_Store`).
- `LICENSE` — Texte de la licence MIT (Copyright © 2026 Viectra).
- `scripts/install.sh` — Compile en release, installe `moonveil` et le lien `mvl` dans `/usr/local/bin`, et accorde optionnellement `CAP_NET_RAW` (`--caps`).
- `scripts/uninstall.sh` — Supprime `/usr/local/bin/moonveil` et `/usr/local/bin/mvl`.
- `src/main.rs` — Point d'entrée du binaire `moonveil` lançant `moonveil::cli::run_cli()` sous `#[tokio::main]`.
- `src/bin/mvl.rs` — Point d'entrée du binaire alias `mvl` déléguant directement à `moonveil::cli::run_cli()`.
- `src/lib.rs` — Racine de la bibliothèque `moonveil` exposant les modules `app`, `cli`, `config`, `net` et `ui`.
- `src/cli/mod.rs` — Racine du module CLI : imports partagés, drapeaux atomiques de signaux (`SHUTDOWN_REQUESTED`, `RESIZE_REQUESTED`) et ré-exports.
- `src/cli/args.rs` — Parsing des options CLI (`CliOptions` : `--demo`, `--export`, `--theme`, `--lang`, presets, ports, watch) et texte d'aide.
- `src/cli/tty.rs` — Cycle de vie terminal (`TerminalGuard`), hooks panic/signaux POSIX et lecture non bloquante du TTY (`poll_tty`).
- `src/cli/input.rs` — Décodeur ANSI/UTF-8 (`AnsiInputParser`) : touches, séquences CSI/SS3 et événements souris SGR.
- `src/cli/runner.rs` — Point d'entrée `run_cli` : export one-shot, initialisation de `App` et boucle d'événements.
- `src/config/mod.rs` — Identifiants visuels (`ThemeId`, `AccentId`, `Language`), helpers TOML/IO et ré-exports du module `config`.
- `src/config/persistence.rs` — Structure `Config`, résolution des chemins XDG et persistance TOML (`config.toml`).
- `src/config/known_hosts.rs` — Registre des hôtes connus/fiables (`KnownHostEntry`, `KnownHostStore`) persisté dans `known_hosts.toml`.
- `src/app/mod.rs` — Types d'état global (`App`, `Tab`, `Modal`, `SocketFilter`) et déclaration des sous-modules du contrôleur.
- `src/app/state.rs` — Construction de `App`, accesseurs (filtres, sélection, interfaces), persistance, toasts et tick d'animation (`on_tick`).
- `src/app/network.rs` — Orchestration réseau : scans réels/démo, ping, traceroute, exports, événements moteur et diff Watch Mode.
- `src/app/input.rs` — Gestion clavier (`handle_key`) et souris (`handle_mouse`, défilement, sélection).
- `src/app/actions.rs` — Exécution des `ClickAction`, fermeture des modales, renommage d'hôte et Wake-on-LAN.
- `src/app/hosts.rs` — Amorçage des hôtes, application des métadonnées d'hôtes connus et ports « en usage » via sockets locaux.
- `src/net/mod.rs` — Déclaration publique des sous-modules réseau (`demo`, `linux`, `model`, `oui`, `scanner`, `tools`).
- `src/net/model/mod.rs` — Racine du modèle : ré-exports et helpers de formatage (`format_mac`, `format_oui`, `parse_mac`, `format_bps`, `format_bytes`).
- `src/net/model/types.rs` — Types réseau (`PortInfo`, `PortState`, `DeviceRole`, `NetworkInterface`, `LocalSocket`, `TimelineEvent`, `NetworkSnapshot`, etc.).
- `src/net/model/host.rs` — Structure `Host` et ses méthodes (affichage, tri, recherche).
- `src/net/model/ports.rs` — `ScanMode`, `ScanPreset`, parsing d'expressions de ports, listes de ports et table des services.
- `src/net/model/inference.rs` — Inférence OS (TTL) et rôle d'équipement, synthèse des hôtes.
- `src/net/linux/mod.rs` — Racine du collecteur télémétrique Linux natif (imports partagés et ré-exports).
- `src/net/linux/system.rs` — Détection de privilèges, horloge, utilisateur/hôte, `/etc/hosts`, `resolv.conf` et passerelles.
- `src/net/linux/interfaces.rs` — Collecte des interfaces (`getifaddrs`, `/sys/class/net`, `/proc/net/dev`) et calculs de préfixes.
- `src/net/linux/proc_net.rs` — Table ARP, sockets locaux `/proc/net/*` et résolution inode → PID.
- `src/net/scanner/mod.rs` — Types du moteur de scan (`EngineEvent`, `ScanConfig`) et construction d'hôtes squelettes.
- `src/net/scanner/engine.rs` — Calcul des cibles, boucle asynchrone `run_scan` et scan concurrent des ports par hôte.
- `src/net/scanner/probes.rs` — Sondes TCP (`InUse`/`Open`/`Closed`/`Filtered`), bannières HTTP/TLS et corrélation aux sockets locaux.
- `src/net/scanner/discovery.rs` — Détection de présence, ping ICMP (TTL), DNS inverse et mDNS.
- `src/net/oui.rs` — Résolution hors-ligne constructeur MAC→OUI via `/usr/share/ieee-data/oui.csv` + table embarquée, et détection des adresses MAC aléatoires (LAA).
- `src/net/tools.rs` — Utilitaires actifs : moniteur Ping RTT continu, traceroute UDP `IP_RECVERR`, Wake-on-LAN, copie presse-papier OSC 52 et export JSON/CSV/Markdown.
- `src/net/demo/mod.rs` — Assemblage du jeu de données simulé déterministe (`build_demo_snapshot`) pour `--demo` et les tests headless.
- `src/net/demo/data.rs` — Données démo statiques (interfaces, sockets, timeline) et constructeurs d'hôtes/ports simulés.
- `src/net/demo/hosts.rs` — Liste des hôtes simulés (LAN, Docker, Tailscale) avec ports et historiques RTT.
- `src/net/demo/simulation.rs` — Animation démo (`tick_demo_snapshot`) et traceroute simulé.
- `src/ui/mod.rs` — Coquille UI Ratatui racine (`render`) : déclaration des sous-modules et routage des 5 onglets.
- `src/ui/layout.rs` — Barre latérale avec emblème, topbar compacte, espace de travail et pied de page de statut.
- `src/ui/splash.rs` — Splash animé de démarrage et écran « terminal trop petit ».
- `src/ui/modals.rs` — Modales flottantes (aide, renommage, ports personnalisés, traceroute) et `centered_rect`.
- `src/ui/hit.rs` — Registre par frame des zones cliquables (`ClickAction`, `HitRegistry`) et des zones de défilement souris (`ScrollTarget`).
- `src/ui/theme.rs` — Palettes TrueColor (`Palette` : Moonveil, Obsidian, Abyss, Graphite, Terminal), accents, styles de cartes et troncature Unicode.
- `src/ui/widgets/mod.rs` — Façade du module `widgets` ré-exportant emblèmes, graphiques et primitives UI.
- `src/ui/widgets/logo.rs` — Grilles et rendu TrueColor demi-blocs du logo Moonveil (compact et hero avec shimmer).
- `src/ui/widgets/charts.rs` — Graphique spline subpixel TrueColor (`SplineChart`) et rééchantillonnage cosinus.
- `src/ui/widgets/primitives.rs` — Interpolation RGB (`mix`), barre d'onde de scan, jauge de ratio de ports et pilule de mode.
- `src/ui/hosts/mod.rs` — Onglet `Hosts` : mise en page et helpers partagés (`push_pill`, `pad_right`).
- `src/ui/hosts/toolbar.rs` — Barre d'outils (recherche, mode Normal/Advanced, scan, preset, watch).
- `src/ui/hosts/table.rs` — Tableau triable des hôtes (en-têtes cliquables et lignes).
- `src/ui/hosts/inspector.rs` — Inspecteur détaillé de l'hôte (métadonnées, courbe RTT, ports filtrables, actions).
- `src/ui/radar.rs` — Onglet `Radar` : grille cliquable `16×16` des adresses `/24` (`.0`–`.255`), pagination `/16` et synthèse topologique par rôle.
- `src/ui/network.rs` — Onglet `Network & Sockets` : métriques d'interfaces, courbes RX/TX temps réel et table des sockets locaux avec PID/processus.
- `src/ui/watch.rs` — Onglet `Watch & Exports` : timeline des changements réseau, liste des hôtes sauvegardés/fiables (avec WoL) et exports en 1 clic.
- `src/ui/settings/mod.rs` — Point d'entrée de l'onglet `Settings` : mise en page responsive et helper partagé `draw_label`.
- `src/ui/settings/scan_options.rs` — Panneau des préférences de scan de l'onglet `Settings` (mode, presets, plage de ports, concurrence/timeout/bannières).
- `src/ui/settings/theme_studio.rs` — Panneau Theme Studio de l'onglet `Settings` (langue, thèmes de surface, couleurs d'accent, animations/splash).
- `tests/engine_tests.rs` — Tests du moteur réseau : parsing de ports, OUI, télémétrie Linux, filtres de recherche et scan TCP loopback.
- `tests/cli_and_export_tests.rs` — Tests d'exports (JSON/CSV/Markdown), persistance TOML (`Config`/`KnownHostStore`) et `AnsiInputParser`.
- `tests/ui_render_tests.rs` — Tests de rendu TUI `TestBackend` multi-tailles/modes/langues, interactions souris (`HitRegistry`) et persistance UI.

## Points d'entrée & Flux principaux

- **Démarrage & CLI** : `src/main.rs` (`moonveil`) et `src/bin/mvl.rs` (`mvl`) appellent `moonveil::cli::run_cli()`. `src/cli.rs` parse les options, charge `Config`, gère l'export direct (`--export`) ou initialise `TerminalGuard` + `App::new(...)` et lance la boucle non-bloquante `poll_tty` → `AnsiInputParser` → `App::handle_key` / `App::handle_mouse` / `App::on_tick` → `ui::render`.
- **Configuration & Persistance** : `src/config/persistence.rs` résout le répertoire via `$MOONVEIL_CONFIG_DIR`, `$XDG_CONFIG_HOME/moonveil` ou `~/.config/moonveil`, et persiste `config.toml` ainsi que `known_hosts.toml` (`src/config/known_hosts.rs`, écritures atomiques).
- **Gestion d'état & Orchestration** : `src/app.rs` (`App`) centralise le `NetworkSnapshot`, l'onglet actif (`Tab`), les modales (`Modal`), le registre `HitRegistry` et un canal `mpsc::unbounded_channel::<EngineEvent>()` recevant les événements des tâches Tokio lancées dans `src/net/scanner.rs`, `src/net/tools.rs` et `src/net/linux.rs` (ou simulées par `src/net/demo.rs`).
- **Build & Tests** : `cargo build --release` (build optimisé), `cargo test` (suites d'intégration dans `tests/engine_tests.rs`, `tests/cli_and_export_tests.rs`, `tests/ui_render_tests.rs`), `cargo fmt --check && cargo clippy --all-targets -- -D warnings` (lint/format via `Makefile`).

## Zones exclues / coûteuses

Ne jamais lire, ouvrir ni scanner récursivement sans autorisation explicite de l'utilisateur :
- `target/` — Artefacts de compilation Rust générés par Cargo (très volumineux).
- `Cargo.lock` — Fichier de verrouillage des dépendances (~47 Ko).
- `assets/` (`assets/moonveil-banner.png`, `assets/moonveil-icon.png`) — Images binaires statiques.
- `.git/` — Métadonnées et historique Git internes.
- Dossiers génériques à ignorer s'ils apparaissent : `node_modules/`, `dist/`, `build/`, `.venv/`.
