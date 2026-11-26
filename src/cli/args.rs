//! Command-line argument parsing and help output.

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

fn next_arg_value(
    flag: &str,
    inline: Option<&str>,
    args: &mut impl Iterator<Item = String>,
) -> Result<String, String> {
    if let Some(val) = inline {
        if val.is_empty() {
            return Err(format!("Empty value for {flag}"));
        }
        return Ok(val.to_string());
    }
    args.next()
        .ok_or_else(|| format!("Missing value after {flag}"))
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
        let (flag, inline) = match arg.split_once('=') {
            Some((k, v)) if k.starts_with("--") => (k, Some(v)),
            _ => (arg.as_str(), None),
        };

        match flag {
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
                opts.iface = Some(next_arg_value(flag, inline, &mut args)?);
            }
            "-p" | "--preset" => {
                let v = next_arg_value(flag, inline, &mut args)?;
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
                let v = next_arg_value(flag, inline, &mut args)?;
                parse_port_expr(&v)?;
                opts.preset = Some(ScanPreset::Custom);
                opts.custom_ports = Some(v);
            }
            "--theme" => {
                let v = next_arg_value(flag, inline, &mut args)?;
                opts.theme = Some(ThemeId::from_cli(&v).ok_or_else(|| {
                    format!("Unknown theme '{v}' (moonveil, obsidian, abyss, graphite, terminal)")
                })?);
            }
            "--accent" => {
                let v = next_arg_value(flag, inline, &mut args)?;
                opts.accent = Some(AccentId::from_cli(&v).ok_or_else(|| {
                    format!("Unknown accent '{v}' (violet, peach, cyan, mint, rose, amber)")
                })?);
            }
            "-l" | "--lang" | "--language" => {
                let v = next_arg_value(flag, inline, &mut args)?;
                opts.language = Some(
                    Language::from_cli(&v)
                        .ok_or_else(|| format!("Unknown language '{v}' (en, fr)"))?,
                );
            }
            "-e" | "--export" => {
                let fmt_s = next_arg_value(flag, inline, &mut args)?;
                let fmt = match fmt_s.trim().to_ascii_lowercase().as_str() {
                    "json" => ExportFormat::Json,
                    "csv" => ExportFormat::Csv,
                    "md" | "markdown" => ExportFormat::Markdown,
                    _ => {
                        return Err(format!(
                            "Unknown export format '{fmt_s}' (expected json, csv, or md)"
                        ));
                    }
                };
                let out_path = args
                    .next()
                    .ok_or_else(|| "Missing output file path after --export <fmt>".to_string())?;
                opts.export_job = Some((fmt, PathBuf::from(out_path)));
            }
            other => {
                return Err(format!("Unknown argument '{other}' (try --help)"));
            }
        }
    }

    Ok(CliParseOutcome::Run(opts))
}

pub fn print_help() {
    println!(
        "\
MOONVEIL (mvl) v{} — Linux Network & Port Discovery TUI by Viectra

USAGE:
  moonveil [OPTIONS]
  mvl [OPTIONS]

OPTIONS:
  --demo                 Run with simulated LAN, Docker, and Tailscale telemetry
  -i, --iface <NAME>     Select starting interface (e.g. enp6s18, wlan0, tailscale0)
  -p, --preset <PRESET>  Port preset: quick, standard, full, webdev, custom
  --ports <EXPR>         Custom port list/ranges (e.g. 22,80,443,8000-8090)
  --theme <THEME>        moonveil, obsidian, abyss, graphite, terminal
  --accent <COLOR>       violet, peach, cyan, mint, rose, amber
  -l, --lang <LANG>      Interface language: en (English, default) or fr (Français)
  --no-splash            Skip the animated launch logo
  -e, --export <FMT> <PATH>
                         Run one scan and export JSON/CSV/Markdown directly
  -h, --help             Print this help message
  -v, --version          Print version info

KEYS & MOUSE:
  1-3 / Tab     Switch views (Hosts, Subnet Radar, Settings)
  s / Space     Start or stop network scan
  p             Cycle port preset (Quick -> Standard -> Full -> WebDev -> Custom)
  r             Deep scan selected host
  /             Focus host search bar (supports port:22, state:in-use, vendor:apple)
  n             Rename selected device
  e             Export snapshot JSON
  ?             Help overlay
  q / Ctrl+C    Quit cleanly",
        env!("CARGO_PKG_VERSION")
    );
}
