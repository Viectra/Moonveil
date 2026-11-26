//! Analyse des arguments de la ligne de commande (`CliOptions`) et texte d'aide.

use super::*;

pub(super) struct CliOptions {
    pub(super) demo_mode: bool,
    pub(super) no_splash: bool,
    pub(super) watch: bool,
    pub(super) iface: Option<String>,
    pub(super) mode: Option<ScanMode>,
    pub(super) preset: Option<ScanPreset>,
    pub(super) custom_ports: Option<String>,
    pub(super) theme: Option<ThemeId>,
    pub(super) accent: Option<AccentId>,
    pub(super) language: Option<Language>,
    pub(super) export_job: Option<(ExportFormat, PathBuf)>,
}

pub(super) enum CliParseOutcome {
    Run(CliOptions),
    ExitZero,
}

pub(super) fn parse_cli() -> Result<CliParseOutcome, String> {
    let mut opts = CliOptions {
        demo_mode: false,
        no_splash: false,
        watch: false,
        iface: None,
        mode: None,
        preset: None,
        custom_ports: None,
        theme: None,
        accent: None,
        language: None,
        export_job: None,
    };

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-v" | "--version" => {
                println!("Moonveil v{} (Viectra)", env!("CARGO_PKG_VERSION"));
                return Ok(CliParseOutcome::ExitZero);
            }
            "-h" | "--help" => {
                print_help();
                return Ok(CliParseOutcome::ExitZero);
            }
            "--demo" => opts.demo_mode = true,
            "--no-splash" => opts.no_splash = true,
            "--watch" => opts.watch = true,
            "--advanced" => opts.mode = Some(ScanMode::Advanced),
            "--normal" => opts.mode = Some(ScanMode::Normal),
            "-i" | "--iface" | "--interface" => {
                let v = args
                    .next()
                    .ok_or_else(|| "Missing interface name after --iface".to_string())?;
                opts.iface = Some(v);
            }
            "--preset" => {
                let v = args
                    .next()
                    .ok_or_else(|| "Missing preset after --preset".to_string())?;
                opts.preset = Some(match v.trim().to_ascii_lowercase().as_str() {
                    "quick" => ScanPreset::Quick,
                    "standard" | "top100" => ScanPreset::Standard,
                    "full" | "top1000" => ScanPreset::Full,
                    "web" | "webdev" => ScanPreset::WebDev,
                    "custom" => ScanPreset::Custom,
                    _ => {
                        return Err(format!(
                            "Unknown preset '{v}' (quick, standard, full, webdev, custom)"
                        ));
                    }
                });
            }
            "--ports" => {
                let v = args
                    .next()
                    .ok_or_else(|| "Missing port expression after --ports".to_string())?;
                parse_port_expr(&v)?;
                opts.preset = Some(ScanPreset::Custom);
                opts.custom_ports = Some(v);
            }
            "--theme" => {
                let v = args
                    .next()
                    .ok_or_else(|| "Missing theme after --theme".to_string())?;
                opts.theme = Some(ThemeId::from_cli(&v).ok_or_else(|| {
                    format!("Unknown theme '{v}' (moonveil, obsidian, abyss, graphite, terminal)")
                })?);
            }
            "--accent" => {
                let v = args
                    .next()
                    .ok_or_else(|| "Missing accent after --accent".to_string())?;
                opts.accent = Some(AccentId::from_cli(&v).ok_or_else(|| {
                    format!("Unknown accent '{v}' (violet, peach, cyan, mint, rose, amber)")
                })?);
            }
            "--lang" => {
                let v = args
                    .next()
                    .ok_or_else(|| "Missing language after --lang".to_string())?;
                opts.language = Some(
                    Language::from_cli(&v)
                        .ok_or_else(|| format!("Unknown language '{v}' (en, fr)"))?,
                );
            }
            "--export" => {
                let fmt_s = args
                    .next()
                    .ok_or_else(|| "Usage: --export <json|csv|md> <output_path>".to_string())?;
                let path_s = args
                    .next()
                    .ok_or_else(|| "Usage: --export <json|csv|md> <output_path>".to_string())?;
                let fmt = match fmt_s.to_ascii_lowercase().as_str() {
                    "json" => ExportFormat::Json,
                    "csv" => ExportFormat::Csv,
                    "md" | "markdown" => ExportFormat::Markdown,
                    _ => return Err(format!("Unsupported export format '{fmt_s}'")),
                };
                opts.export_job = Some((fmt, PathBuf::from(path_s)));
            }
            other => {
                return Err(format!(
                    "Unknown argument '{other}'. Run 'moonveil --help' for usage."
                ));
            }
        }
    }
    Ok(CliParseOutcome::Run(opts))
}

pub(super) fn print_help() {
    println!(
        "\
Moonveil (mvl) v{} — Clickable terminal network scanner, subnet radar & socket inspector

USAGE:
    moonveil [OPTIONS]
    mvl [OPTIONS]

OPTIONS:
    --demo                        Run with realistic simulated LAN & Docker telemetry
    -i, --iface <NAME>            Select initial network interface (e.g. enp6s18, wlan0)
    --normal / --advanced         Start in Normal Mode or Advanced Mode
    --preset <PRESET>             quick | standard | full | webdev | custom
    --ports <EXPR>                Custom ports (e.g. 22,80,443,8000-8090)
    --watch                       Enable background Watch Mode on startup
    --theme <THEME>               moonveil | obsidian | abyss | graphite | terminal
    --accent <COLOR>              violet | peach | cyan | mint | rose | amber
    --lang <LANG>                 Interface language: en | fr
    --no-splash                   Skip the animated launch logo reveal
    --export <FMT> <PATH>         Run one-shot scan and write json, csv, or md report
    -h, --help                    Print this help message
    -v, --version                 Print version information",
        env!("CARGO_PKG_VERSION")
    );
}
