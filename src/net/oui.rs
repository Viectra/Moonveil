//! Offline IEEE OUI MAC-to-vendor lookup using `/usr/share/ieee-data/oui.csv` plus embedded prefixes.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::OnceLock;

static OUI_DB: OnceLock<OuiDb> = OnceLock::new();

#[derive(Debug)]
struct OuiDb {
    entries: Vec<([u8; 3], String)>,
}

impl OuiDb {
    fn load() -> Self {
        let mut entries = load_csv_file(Path::new("/usr/share/ieee-data/oui.csv"))
            .or_else(|| load_csv_file(Path::new("/usr/share/misc/oui.csv")))
            .unwrap_or_default();

        // Append embedded curated entries so common virtual/container/consumer OUIs always resolve.
        for &(prefix, name) in BUILTIN_OUIS {
            entries.push((prefix, name.to_string()));
        }

        entries.sort_by_key(|a| a.0);
        entries.dedup_by(|a, b| a.0 == b.0);
        Self { entries }
    }

    fn find(&self, prefix: [u8; 3]) -> Option<&str> {
        self.entries
            .binary_search_by_key(&prefix, |item| item.0)
            .ok()
            .map(|idx| self.entries[idx].1.as_str())
    }
}

/// Looks up the hardware vendor for a 6-byte MAC address and detects randomized LAA MACs.
pub fn lookup_vendor(mac: [u8; 6]) -> (Option<String>, bool) {
    let prefix = [mac[0], mac[1], mac[2]];
    let db = OUI_DB.get_or_init(OuiDb::load);
    if let Some(vendor) = db.find(prefix) {
        return (Some(shorten_vendor(vendor)), false);
    }
    // Check locally administered bit (bit 1 of first octet) when no vendor OUI matched.
    let randomized = (mac[0] & 0x02) != 0 && (mac[0] & 0x01) == 0;
    if randomized {
        (Some("Private / Randomized MAC".to_string()), true)
    } else {
        (None, false)
    }
}

/// Parses an IEEE `oui.csv` formatted string into sorted `(prefix, vendor)` entries.
pub fn parse_oui_csv<R: BufRead>(reader: R) -> Vec<([u8; 3], String)> {
    let mut out = Vec::with_capacity(4096);
    for (idx, line) in reader.lines().enumerate() {
        let Ok(line) = line else { continue };
        if idx == 0 && line.starts_with("Registry,") {
            continue;
        }
        let fields = parse_csv_row(&line);
        if fields.len() < 3 {
            continue;
        }
        let hex = fields[1].trim();
        if hex.len() != 6 {
            continue;
        }
        let Some(prefix) = parse_oui_hex(hex) else {
            continue;
        };
        let org = fields[2].trim();
        if !org.is_empty() {
            out.push((prefix, org.to_string()));
        }
    }
    out
}

fn load_csv_file(path: &Path) -> Option<Vec<([u8; 3], String)>> {
    let file = File::open(path).ok()?;
    let reader = BufReader::new(file);
    let parsed = parse_oui_csv(reader);
    if parsed.is_empty() {
        None
    } else {
        Some(parsed)
    }
}

fn parse_oui_hex(hex: &str) -> Option<[u8; 3]> {
    let b0 = u8::from_str_radix(&hex[0..2], 16).ok()?;
    let b1 = u8::from_str_radix(&hex[2..4], 16).ok()?;
    let b2 = u8::from_str_radix(&hex[4..6], 16).ok()?;
    Some([b0, b1, b2])
}

fn parse_csv_row(line: &str) -> Vec<String> {
    let mut fields = Vec::with_capacity(4);
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' {
            if in_quotes && chars.peek() == Some(&'"') {
                cur.push('"');
                chars.next();
            } else {
                in_quotes = !in_quotes;
            }
        } else if c == ',' && !in_quotes {
            fields.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    fields.push(cur);
    fields
}

fn shorten_vendor(raw: &str) -> String {
    let mut s = raw.trim().to_string();
    for suffix in [
        ", Inc.",
        " Inc.",
        " Inc",
        ", Corp.",
        " Corp.",
        " Corporation",
        ", Ltd.",
        " Ltd.",
        " Co., Ltd.",
        " LLC",
        " GmbH",
    ] {
        if let Some(stripped) = s.strip_suffix(suffix) {
            s = stripped.trim().to_string();
        }
    }
    s
}

/// Curated fallback database covering hypervisors, routers, servers, SBCs, phones, and IoT.
const BUILTIN_OUIS: &[([u8; 3], &str)] = &[
    ([0x00, 0x03, 0x93], "Apple"),
    ([0x00, 0x05, 0x69], "VMware"),
    ([0x00, 0x0C, 0x29], "VMware"),
    ([0x00, 0x0D, 0x3A], "Microsoft Azure"),
    ([0x00, 0x11, 0x32], "Synology"),
    ([0x00, 0x15, 0x5D], "Microsoft Hyper-V"),
    ([0x00, 0x16, 0x3E], "Xen / XCP-ng"),
    ([0x00, 0x17, 0x88], "Philips Hue"),
    ([0x00, 0x1A, 0x11], "Google"),
    ([0x00, 0x1B, 0x21], "Intel"),
    ([0x00, 0x1C, 0x42], "Parallels"),
    ([0x00, 0x1E, 0x67], "Intel"),
    ([0x00, 0x24, 0xE8], "Dell"),
    ([0x00, 0x25, 0x90], "Supermicro"),
    ([0x00, 0x50, 0x56], "VMware"),
    ([0x00, 0xE0, 0x4C], "Realtek"),
    ([0x02, 0x42, 0xAC], "Docker Container"),
    ([0x04, 0xD4, 0xC4], "ASUS"),
    ([0x08, 0x00, 0x27], "VirtualBox"),
    ([0x0C, 0x4D, 0xE9], "Apple"),
    ([0x10, 0xBF, 0x48], "ASUS"),
    ([0x14, 0x0C, 0x76], "Freebox / Iliad"),
    ([0x14, 0xCC, 0x20], "TP-Link"),
    ([0x18, 0xE8, 0x29], "Ubiquiti"),
    ([0x1C, 0x69, 0x7A], "Intel"),
    ([0x24, 0x0A, 0xC4], "Espressif IoT"),
    ([0x24, 0x5E, 0xBE], "QNAP"),
    ([0x28, 0xCF, 0xE9], "Apple"),
    ([0x2C, 0xCF, 0x67], "Raspberry Pi"),
    ([0x30, 0xAE, 0xA4], "Espressif IoT"),
    ([0x34, 0x27, 0x92], "Freebox / Iliad"),
    ([0x34, 0x97, 0xF6], "ASUS"),
    ([0x38, 0x07, 0x16], "Freebox / Iliad"),
    ([0x38, 0xF9, 0xD3], "Apple"),
    ([0x3C, 0x22, 0xFB], "Apple"),
    ([0x40, 0xB0, 0x34], "HP"),
    ([0x44, 0xD9, 0xE7], "Ubiquiti"),
    ([0x48, 0x2C, 0xA0], "Xiaomi"),
    ([0x4C, 0x5E, 0x0C], "MikroTik"),
    ([0x50, 0xC7, 0xBF], "TP-Link"),
    ([0x52, 0x54, 0x00], "QEMU / KVM"),
    ([0x58, 0xEF, 0x68], "Linksys"),
    ([0x60, 0x38, 0xE0], "Belkin"),
    ([0x64, 0x16, 0x7F], "Polycom"),
    ([0x68, 0xFF, 0x7B], "TP-Link"),
    ([0x6C, 0x4B, 0x90], "Lenovo"),
    ([0x70, 0x85, 0xC2], "ASRock"),
    ([0x74, 0x83, 0xC2], "Ubiquiti"),
    ([0x78, 0x8A, 0x20], "Ubiquiti"),
    ([0x7C, 0x2E, 0xBD], "Google"),
    ([0x80, 0x2A, 0xA8], "Ubiquiti"),
    ([0x84, 0xD8, 0x1B], "TP-Link"),
    ([0x88, 0x66, 0x5A], "Apple"),
    ([0x8C, 0x85, 0x90], "Apple"),
    ([0x90, 0x09, 0xD0], "Synology"),
    ([0x94, 0x83, 0xC4], "GL.iNet"),
    ([0x98, 0xDA, 0xC4], "TP-Link"),
    ([0x9C, 0xB6, 0xD0], "Rivet Networks"),
    ([0xA0, 0x20, 0xA6], "Espressif IoT"),
    ([0xA4, 0x83, 0xE7], "Apple"),
    ([0xA8, 0x5E, 0x45], "ASUS"),
    ([0xAC, 0x84, 0xC6], "TP-Link"),
    ([0xB0, 0xBE, 0x76], "TP-Link"),
    ([0xB4, 0x2E, 0x99], "Gigabyte"),
    ([0xB8, 0x27, 0xEB], "Raspberry Pi"),
    ([0xBC, 0x24, 0x11], "Proxmox / QEMU"),
    ([0xC0, 0x56, 0x27], "Belkin"),
    ([0xC4, 0xAD, 0x34], "MikroTik"),
    ([0xC8, 0x7F, 0x54], "ASUS"),
    ([0xCC, 0x28, 0xAA], "ASUS"),
    ([0xD0, 0x50, 0x99], "ASRock"),
    ([0xD4, 0xCA, 0x6D], "MikroTik"),
    ([0xD8, 0x3A, 0xDD], "Raspberry Pi"),
    ([0xDC, 0xA6, 0x32], "Raspberry Pi"),
    ([0xE0, 0x63, 0xDA], "Ubiquiti"),
    ([0xE4, 0x5F, 0x01], "Raspberry Pi"),
    ([0xE8, 0x9F, 0x80], "TP-Link"),
    ([0xEC, 0x08, 0x6B], "TP-Link"),
    ([0xF0, 0x9F, 0xC2], "Ubiquiti"),
    ([0xF4, 0xF2, 0x6D], "TP-Link"),
    ([0xF8, 0x1A, 0x67], "TP-Link"),
    ([0xFC, 0xEC, 0xDA], "Ubiquiti"),
];
