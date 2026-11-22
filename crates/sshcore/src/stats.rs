//! Lightweight, agentless Linux server resource sampling over an existing SSH session.
//!
//! Runs a single read-only command over an SSH exec channel (no remote agent,
//! no extra TCP connection) and parses `/proc/stat`, `/proc/meminfo`,
//! `/proc/loadavg`, and `df -Pk /`. Non-Linux targets simply return `None`.

use serde::Serialize;

/// Single read-only shell snippet executed on a separate SSH exec channel.
pub const STATS_CMD: &str = concat!(
    "awk '/^cpu /{print \"CPU\",$2+$3+$4+$5+$6+$7+$8,$5+$6; exit}' /proc/stat 2>/dev/null; ",
    "awk '/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2} /^MemFree:/{f=$2} END{if(t>0) print \"MEM\",t,(a>0?a:f)}' /proc/meminfo 2>/dev/null; ",
    "awk '{print \"LOAD\",$1}' /proc/loadavg 2>/dev/null; ",
    "df -Pk / 2>/dev/null | awk 'NR==2{print \"DISK\",$2,$3}'"
);

/// Snapshot of basic server metrics. Any unavailable field is `None`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ServerStats {
    pub cpu_total: Option<u64>,
    pub cpu_idle: Option<u64>,
    pub load_1m: Option<f32>,
    pub mem_used_kb: Option<u64>,
    pub mem_total_kb: Option<u64>,
    pub disk_used_kb: Option<u64>,
    pub disk_total_kb: Option<u64>,
}

/// Parses the output of [`STATS_CMD`]. Returns `None` if no metric could be parsed
/// (for example on Windows, network appliances, or restricted shells).
pub fn parse_stats(output: &str) -> Option<ServerStats> {
    let mut s = ServerStats {
        cpu_total: None,
        cpu_idle: None,
        load_1m: None,
        mem_used_kb: None,
        mem_total_kb: None,
        disk_used_kb: None,
        disk_total_kb: None,
    };
    for line in output.lines() {
        let mut parts = line.split_whitespace();
        match parts.next() {
            Some("CPU") => {
                if let (Some(t), Some(i)) = (parts.next().and_then(|v| v.parse().ok()), parts.next().and_then(|v| v.parse().ok())) {
                    s.cpu_total = Some(t);
                    s.cpu_idle = Some(i);
                }
            }
            Some("MEM") => {
                if let (Some(total), Some(avail)) = (parts.next().and_then(|v| v.parse::<u64>().ok()), parts.next().and_then(|v| v.parse::<u64>().ok())) {
                    if total > 0 {
                        s.mem_total_kb = Some(total);
                        s.mem_used_kb = Some(total.saturating_sub(avail));
                    }
                }
            }
            Some("LOAD") => {
                if let Some(l) = parts.next().and_then(|v| v.parse::<f32>().ok()) {
                    if l.is_finite() && l >= 0.0 {
                        s.load_1m = Some(l);
                    }
                }
            }
            Some("DISK") => {
                if let (Some(total), Some(used)) = (parts.next().and_then(|v| v.parse::<u64>().ok()), parts.next().and_then(|v| v.parse::<u64>().ok())) {
                    if total > 0 {
                        s.disk_total_kb = Some(total);
                        s.disk_used_kb = Some(used.min(total));
                    }
                }
            }
            _ => {}
        }
    }
    if s.cpu_total.is_some() || s.mem_total_kb.is_some() || s.load_1m.is_some() || s.disk_total_kb.is_some() {
        Some(s)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_linux_output() {
        let out = "CPU 123456 100000\nMEM 8192000 3072000\nLOAD 0.42\nDISK 52428800 20971520\n";
        let s = parse_stats(out).expect("parsed");
        assert_eq!(s.cpu_total, Some(123456));
        assert_eq!(s.cpu_idle, Some(100000));
        assert_eq!(s.mem_total_kb, Some(8192000));
        assert_eq!(s.mem_used_kb, Some(5120000));
        assert_eq!(s.load_1m, Some(0.42));
        assert_eq!(s.disk_total_kb, Some(52428800));
        assert_eq!(s.disk_used_kb, Some(20971520));
    }

    #[test]
    fn non_linux_or_empty_returns_none() {
        assert_eq!(parse_stats(""), None);
        assert_eq!(parse_stats("The syntax of the command is incorrect.\r\n"), None);
    }
}
