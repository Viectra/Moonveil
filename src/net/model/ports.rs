//! Modes et presets de scan, parsing d'expressions de ports et table des services connus.

use super::*;

/// Display & control density mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ScanMode {
    #[default]
    Normal,
    Advanced,
}

impl ScanMode {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Normal => "Normal",
            Self::Advanced => "Advanced",
        }
    }

    pub const fn subtitle(self) -> &'static str {
        match self {
            Self::Normal => "Clean Radar",
            Self::Advanced => "Deep Recon",
        }
    }

    pub const fn label_for(self, lang: Language) -> &'static str {
        match self {
            Self::Normal => "Normal",
            Self::Advanced => lang.t("Advanced", "Avancé"),
        }
    }

    pub const fn subtitle_for(self, lang: Language) -> &'static str {
        match self {
            Self::Normal => lang.t("Clean Radar", "Radar épuré"),
            Self::Advanced => lang.t("Deep Recon", "Recon approfondie"),
        }
    }

    pub const fn toggle(self) -> Self {
        match self {
            Self::Normal => Self::Advanced,
            Self::Advanced => Self::Normal,
        }
    }
}

/// Port scan target preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ScanPreset {
    #[default]
    Quick,
    Standard,
    Full,
    WebDev,
    Custom,
}

impl ScanPreset {
    pub const ALL: &'static [Self] = &[
        Self::Quick,
        Self::Standard,
        Self::Full,
        Self::WebDev,
        Self::Custom,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Quick => "Quick (32)",
            Self::Standard => "Standard (100)",
            Self::Full => "Full (1000)",
            Self::WebDev => "Web & Dev",
            Self::Custom => "Custom",
        }
    }

    pub const fn short_label(self) -> &'static str {
        match self {
            Self::Quick => "Quick",
            Self::Standard => "Top 100",
            Self::Full => "Top 1000",
            Self::WebDev => "Web/Dev",
            Self::Custom => "Custom",
        }
    }

    pub const fn label_for(self, lang: Language) -> &'static str {
        match self {
            Self::Quick => lang.t("Quick (32)", "Rapide (32)"),
            Self::Standard => self.label(),
            Self::Full => lang.t("Full (1000)", "Complet (1000)"),
            Self::WebDev => self.label(),
            Self::Custom => lang.t("Custom", "Perso"),
        }
    }

    pub const fn short_label_for(self, lang: Language) -> &'static str {
        match self {
            Self::Quick => lang.t("Quick", "Rapide"),
            Self::Custom => lang.t("Custom", "Perso"),
            _ => self.short_label(),
        }
    }

    pub const fn next(self) -> Self {
        match self {
            Self::Quick => Self::Standard,
            Self::Standard => Self::Full,
            Self::Full => Self::WebDev,
            Self::WebDev => Self::Custom,
            Self::Custom => Self::Quick,
        }
    }
}

/// Parses a custom port specification string (e.g. `22,80,443,8000-8010`).
pub fn parse_port_expr(expr: &str) -> Result<Vec<u16>, String> {
    let mut set = BTreeSet::new();
    let trimmed = expr.trim();
    if trimmed.is_empty() {
        return Err("Port list cannot be empty".to_string());
    }
    for part in trimmed.split(',') {
        let token = part.trim();
        if token.is_empty() {
            continue;
        }
        if let Some((start_s, end_s)) = token.split_once('-') {
            let start: u16 = start_s
                .trim()
                .parse()
                .map_err(|_| format!("Invalid start port '{start_s}'"))?;
            let end: u16 = end_s
                .trim()
                .parse()
                .map_err(|_| format!("Invalid end port '{end_s}'"))?;
            if start == 0 || end == 0 || start > end {
                return Err(format!("Invalid range '{token}' (must be 1..=65535)"));
            }
            if usize::from(end - start) > 20_000 && set.len() + usize::from(end - start) > 65_535 {
                return Err("Range too large".to_string());
            }
            for port in start..=end {
                set.insert(port);
            }
        } else {
            let port: u16 = token
                .parse()
                .map_err(|_| format!("Invalid port '{token}'"))?;
            if port == 0 {
                return Err("Port 0 is not scannable".to_string());
            }
            set.insert(port);
        }
    }
    if set.is_empty() {
        return Err("No valid ports parsed".to_string());
    }
    Ok(set.into_iter().collect())
}

/// Quick top-32 port list.
pub const QUICK_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 548, 631, 993, 995, 1433, 1883,
    2049, 3000, 3306, 3389, 5000, 5432, 5900, 6379, 8000, 8080, 8443, 9000, 27017,
];

/// Web, API, DB, container, and media development port list.
pub const WEB_DEV_PORTS: &[u16] = &[
    22, 53, 80, 81, 300, 443, 1883, 2375, 2376, 3000, 3001, 3306, 4000, 4200, 5000, 5173, 5432,
    5672, 6379, 7000, 8000, 8006, 8008, 8080, 8081, 8096, 8443, 8888, 9000, 9090, 9200, 9443,
    11434, 27017,
];

/// Standard top-100 TCP ports.
pub const STANDARD_TOP_100_PORTS: &[u16] = &[
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143,
    144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646,
    873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1883, 1900,
    2000, 2001, 2049, 2121, 2375, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5353, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6379, 6646, 7070, 8000, 8006,
    8008, 8009, 8080, 8081, 8443, 8888, 9000, 9090, 9100, 9999, 27017,
];

/// Generates the concrete port list for a given preset and custom expression.
pub fn ports_for_preset(preset: ScanPreset, custom_expr: &str) -> Vec<u16> {
    match preset {
        ScanPreset::Quick => QUICK_PORTS.to_vec(),
        ScanPreset::Standard => STANDARD_TOP_100_PORTS.to_vec(),
        ScanPreset::WebDev => WEB_DEV_PORTS.to_vec(),
        ScanPreset::Full => {
            let mut set: BTreeSet<u16> = (1..=1000).collect();
            for &p in WEB_DEV_PORTS {
                set.insert(p);
            }
            for &p in &[1433, 1521, 2049, 3389, 5900, 62078] {
                set.insert(p);
            }
            set.into_iter().take(1024).collect()
        }
        ScanPreset::Custom => parse_port_expr(custom_expr).unwrap_or_else(|_| QUICK_PORTS.to_vec()),
    }
}

/// Maps common ports to `(service_name, plain_english_description)`.
pub fn service_info(port: u16) -> (&'static str, &'static str) {
    match port {
        21 => ("ftp", "File Transfer Protocol"),
        22 | 2222 => ("ssh", "Secure Shell remote login"),
        23 => ("telnet", "Unencrypted legacy terminal"),
        25 | 587 => ("smtp", "Mail transfer server"),
        53 => ("dns", "Domain Name System resolver"),
        67 | 68 => ("dhcp", "Dynamic IP lease server"),
        80 | 81 | 8008 => ("http", "Unencrypted web server"),
        110 => ("pop3", "Email retrieval service"),
        111 => ("rpcbind", "ONC RPC portmapper"),
        123 => ("ntp", "Network Time synchronization"),
        135 => ("msrpc", "Windows RPC endpoint mapper"),
        139 => ("netbios", "NetBIOS file/name session"),
        143 => ("imap", "Mail access server"),
        161 => ("snmp", "Network device telemetry"),
        389 => ("ldap", "Directory authentication service"),
        443 => ("https", "Encrypted HTTPS web server"),
        445 => ("smb", "Windows / Samba file sharing"),
        548 => ("afp", "Apple Filing Protocol share"),
        554 => ("rtsp", "Media / camera video stream"),
        631 => ("ipp", "Network printing (CUPS)"),
        873 => ("rsync", "Remote file synchronization"),
        993 => ("imaps", "Encrypted IMAP mail"),
        995 => ("pop3s", "Encrypted POP3 mail"),
        1433 => ("mssql", "Microsoft SQL Server"),
        1883 => ("mqtt", "IoT telemetry message broker"),
        1900 => ("upnp", "UPnP / SSDP device discovery"),
        2049 => ("nfs", "Network File System share"),
        2375 | 2376 => ("docker", "Docker container engine API"),
        3000 | 5173 => ("dev-web", "Frontend / Node dev server"),
        3128 => ("proxy", "HTTP caching proxy"),
        3306 => ("mysql", "MySQL / MariaDB database"),
        3389 => ("rdp", "Windows Remote Desktop"),
        5000 => ("upnp/api", "Local API / Synology DSM / Flask"),
        5353 => ("mdns", "Multicast DNS (.local) discovery"),
        5357 => ("wsd", "Windows Web Services Discovery"),
        5432 => ("postgres", "PostgreSQL relational database"),
        5672 => ("amqp", "RabbitMQ message queue"),
        5900 => ("vnc", "Graphical remote screen sharing"),
        6379 => ("redis", "In-memory key-value datastore"),
        8000 => ("http-alt", "Application / Python web server"),
        8006 => ("proxmox", "Proxmox VE virtualization UI"),
        8080 | 8081 => ("http-proxy", "Web service or reverse proxy"),
        8096 => ("jellyfin", "Media streaming server"),
        8443 | 9443 => ("https-alt", "Encrypted management web UI"),
        8888 => ("notebook", "Jupyter / web control panel"),
        9000 => ("portainer", "Admin web portal / PHP-FPM"),
        9090 => ("prometheus", "Metrics / Cockpit web console"),
        9100 => ("jetdirect", "Raw network printer port"),
        9200 => ("elastic", "Elasticsearch HTTP API"),
        11434 => ("ollama", "Local inference API endpoint"),
        27017 => ("mongodb", "MongoDB document database"),
        62078 => ("iphone-sync", "Apple mobile wireless sync"),
        _ => ("unknown", "Listening TCP service"),
    }
}
