use std::process::{Command, Stdio};
use std::io::Write;
use std::collections::HashMap;
use anyhow::{Result, anyhow};
use serde_json::Value;

pub struct NftablesClassifier {
    table_name: String,
    chain_name: String,
    stats_chain: String,
}

#[derive(Debug, Clone)]
pub struct TrafficRule {
    pub name: String,
    pub protocol: String,
    pub ports: Vec<u16>,
    pub ip_ranges: Vec<String>,
    pub payload_patterns: Vec<String>,
    pub action: String,
}

impl NftablesClassifier {
    pub fn new(table_name: &str, chain_name: &str) -> Self {
        Self {
            table_name: table_name.to_string(),
            chain_name: chain_name.to_string(),
            stats_chain: "traffic_stats".to_string(),
        }
    }

    pub fn initialize(&self) -> Result<()> {
        self.cleanup()?;
        self.create_base_structure()?;
        self.create_statistics_chain()?;
        Ok(())
    }

    fn create_base_structure(&self) -> Result<()> {
        let commands = vec![
            // 創建主表格
            format!("add table inet {}", self.table_name),
            
            // 創建主過濾鏈
            format!(
                "add chain inet {} {} {{ type filter hook forward priority 0; policy accept; }}",
                self.table_name, self.chain_name
            ),
            
            // 創建用於統計的鏈
            format!(
                "add chain inet {} {}",
                self.table_name, self.stats_chain
            ),
            
            // 在主鏈中跳轉到統計鏈
            format!(
                "add rule inet {} {} jump {}",
                self.table_name, self.chain_name, self.stats_chain
            ),
            
            // 創建各種集合
            format!(
                "add set inet {} netflix_ips {{ type ipv4_addr; flags interval; elements {{ {} }} }}",
                self.table_name,
                vec![
                    "108.175.32.0/20",
                    "198.38.96.0/19", 
                    "198.45.48.0/20",
                    "208.75.76.0/22",
                    "208.75.80.0/20"
                ].join(", ")
            ),
            
            format!(
                "add set inet {} youtube_ips {{ type ipv4_addr; flags interval; elements {{ {} }} }}",
                self.table_name,
                vec![
                    "173.194.0.0/16",
                    "74.125.0.0/16",
                    "216.58.0.0/16",
                    "172.217.0.0/16"
                ].join(", ")
            ),
            
            format!(
                "add set inet {} streaming_ports {{ type inet_service; elements {{ {} }} }}",
                self.table_name,
                vec![80, 443, 1935, 8080, 8000, 8008].iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            
            // 創建動態阻止集合
            format!(
                "add set inet {} dynamic_block {{ type ipv4_addr; flags timeout; }}",
                self.table_name
            ),
            
            // 創建用戶 MAC 地址集合
            format!(
                "add set inet {} user_mac {{ type ether_addr; }}",
                self.table_name
            ),
        ];

        for cmd in commands {
            self.nft_cmd(&cmd)?;
        }

        Ok(())
    }

    fn create_statistics_chain(&self) -> Result<()> {
        // 為 Netflix 流量創建計數器和規則
        let netflix_rules = vec![
            // 基於 IP 範圍的 Netflix 識別
            format!(
                "ip daddr @netflix_ips tcp dport @streaming_ports counter accept comment \"Netflix traffic\""
            ),
            format!(
                "ip saddr @netflix_ips tcp sport @streaming_ports counter accept comment \"Netflix response\""
            ),
            
            // 基於 IP 範圍的 YouTube 識別
            format!(
                "ip daddr @youtube_ips tcp dport @streaming_ports counter accept comment \"YouTube traffic\""
            ),
            format!(
                "ip saddr @youtube_ips tcp sport @streaming_ports counter accept comment \"YouTube response\""
            ),
        ];

        for rule in netflix_rules {
            let full_rule = format!(
                "add rule inet {} {} {}",
                self.table_name, self.stats_chain, rule
            );
            self.nft_cmd(&full_rule)?;
        }

        Ok(())
    }

    pub fn add_traffic_rule(&self, rule: &TrafficRule) -> Result<()> {
        let match_conditions = self.build_match_conditions(rule);
        let full_rule = format!(
            "add rule inet {} {} {} {} comment \"{}\"",
            self.table_name, self.stats_chain, match_conditions, rule.action, rule.name
        );
        
        self.nft_cmd(&full_rule)
    }

    fn build_match_conditions(&self, rule: &TrafficRule) -> String {
        let mut conditions = Vec::new();

        // 協議條件
        match rule.protocol.as_str() {
            "tcp" => conditions.push("tcp".to_string()),
            "udp" => conditions.push("udp".to_string()),
            "any" => {}, // 任何協議
            _ => conditions.push(format!("meta l4proto {}", rule.protocol)),
        }

        // 端口條件
        if !rule.ports.is_empty() {
            let ports_str = rule.ports.iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            conditions.push(format!("tcp dport {{ {} }}", ports_str));
        }

        // IP 範圍條件
        for ip_range in &rule.ip_ranges {
            conditions.push(format!("ip daddr {}", ip_range));
        }

        // 負載模式匹配（簡單版本）
        for pattern in &rule.payload_patterns {
            // 注意：這需要 nftables 支持 payload 匹配
            conditions.push(format!("tcp payload ~ \"{}\"", pattern));
        }

        conditions.join(" ")
    }

    pub fn add_time_based_rule(&self, service: &str, start_time: &str, end_time: &str) -> Result<()> {
        let rule = format!(
            "add rule inet {} {} meta hour >= \"{}\" meta hour < \"{}\" ip daddr @{}_ips drop comment \"Time block: {}\"",
            self.table_name, self.stats_chain, start_time, end_time, service, service
        );
        self.nft_cmd(&rule)
    }

    pub fn add_user_restriction(&self, mac_addr: &str, services: &[String]) -> Result<()> {
        // 首先將 MAC 地址添加到集合
        let add_mac = format!(
            "add element inet {} user_mac {{ {} }}",
            self.table_name, mac_addr
        );
        self.nft_cmd(&add_mac)?;

        // 為每個服務創建阻止規則
        for service in services {
            let rule = format!(
                "add rule inet {} {} ether saddr {} ip daddr @{}_ips drop comment \"User block: {} for {}\"",
                self.table_name, self.stats_chain, mac_addr, service, service, mac_addr
            );
            self.nft_cmd(&rule)?;
        }

        Ok(())
    }

    pub fn block_ip_temporarily(&self, ip: &str, duration_seconds: u32) -> Result<()> {
        let cmd = format!(
            "add element inet {} dynamic_block {{ {} timeout {}s }}",
            self.table_name, ip, duration_seconds
        );
        self.nft_cmd(&cmd)
    }

    pub fn get_traffic_stats(&self) -> Result<HashMap<String, u64>> {
        let output = Command::new("nft")
            .args(&["list", "ruleset", "-a"])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to get nftables rules"));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        self.parse_counter_stats(&output_str)
    }

    fn parse_counter_stats(&self, ruleset: &str) -> Result<HashMap<String, u64>> {
        let mut stats = HashMap::new();
        let counter_re = regex::Regex::new(r"counter packets (\d+) bytes (\d+).*comment \"([^\"]+)\"")?;

        for line in ruleset.lines() {
            if let Some(caps) = counter_re.captures(line) {
                if let (Some(packets), Some(service)) = (caps.get(1), caps.get(3)) {
                    let service_name = service.as_str().to_string();
                    let packet_count: u64 = packets.as_str().parse().unwrap_or(0);
                    
                    // 只統計我們感興趣的服務
                    if service_name.contains("traffic") {
                        stats.insert(service_name, packet_count);
                    }
                }
            }
        }

        Ok(stats)
    }

    pub fn create_payload_matching_rule(&self, name: &str, pattern: &str, action: &str) -> Result<()> {
        // 使用 nftables 的 payload 匹配來實現類似 L7-filter 的功能
        let rule = format!(
            "add rule inet {} {} tcp dport @streaming_ports @th,64,128 \"{}\" {} comment \"Payload match: {}\"",
            self.table_name, self.stats_chain, pattern, action, name
        );
        
        self.nft_cmd(&rule)
    }

    pub fn create_dns_filtering_rule(&self, domain: &str, action: &str) -> Result<()> {
        // 過濾 DNS 查詢（UDP 端口 53）
        let rule = format!(
            "add rule inet {} {} udp dport 53 @th,64,512 \"{}\" {} comment \"DNS filter: {}\"",
            self.table_name, self.stats_chain, domain, action, domain
        );
        
        self.nft_cmd(&rule)
    }

    fn nft_cmd(&self, command: &str) -> Result<()> {
        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(command.as_bytes())?;
        }

        let output = child.wait_with_output()?;
        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("nftables command failed: {}\nError: {}", command, error_msg));
        }

        Ok(())
    }

    pub fn cleanup(&self) -> Result<()> {
        // 刪除表格（會自動刪除所有相關規則和集合）
        let _ = self.nft_cmd(&format!("delete table inet {}", self.table_name));
        Ok(())
    }
}