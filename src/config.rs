use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub interface: String,
    pub report_interval: u64,
    pub log_unknown_traffic: bool,
    pub filter: Option<String>,
    pub services: Vec<ServiceConfig>,
    pub time_rules: Vec<TimeRule>,
    pub user_rules: Vec<UserRule>,
    pub blocked_domains: Vec<String>,
    pub pattern_rules: Vec<PatternRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceConfig {
    pub name: String,
    pub ports: Vec<u16>,
    pub ip_ranges: Vec<String>,
    pub blocked: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TimeRule {
    pub start_time: String,
    pub end_time: String,
    pub services: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserRule {
    pub mac_address: String,
    pub name: String,
    pub blocked_services: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PatternRule {
    pub name: String,
    pub pattern: String,
    pub action: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interface: "br-lan".to_string(),
            report_interval: 60,
            log_unknown_traffic: false,
            filter: Some("tcp or udp".to_string()),
            services: vec![
                ServiceConfig {
                    name: "netflix".to_string(),
                    ports: vec![80, 443, 1935],
                    ip_ranges: vec![
                        "108.175.32.0/20".to_string(),
                        "198.38.96.0/19".to_string(),
                    ],
                    blocked: false,
                },
                ServiceConfig {
                    name: "youtube".to_string(),
                    ports: vec![80, 443, 1935],
                    ip_ranges: vec![
                        "173.194.0.0/16".to_string(),
                        "74.125.0.0/16".to_string(),
                    ],
                    blocked: false,
                },
            ],
            time_rules: vec![],
            user_rules: vec![],
            blocked_domains: vec![
                "netflix.com".to_string(),
                "nflxvideo.net".to_string(),
            ],
            pattern_rules: vec![
                PatternRule {
                    name: "netflix_pattern".to_string(),
                    pattern: "netflix".to_string(),
                    action: "drop".to_string(),
                },
            ],
        }
    }
}

impl Config {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let config_paths = vec![
            "/etc/config/trafficmon.conf",
            "./config/trafficmon.conf",
        ];
        
        for path in config_paths {
            if Path::new(path).exists() {
                let content = fs::read_to_string(path)?;
                return Ok(toml::from_str(&content)?);
            }
        }
        
        println!("No config file found, using defaults");
        Ok(Config::default())
    }
}