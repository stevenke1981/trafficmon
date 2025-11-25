use pcap::{Capture, Device};
use std::collections::HashMap;
use std::sync::Arc;
use std::net::Ipv4Addr;

use crate::config::Config;
use crate::stats::TrafficStats;

pub struct TrafficClassifier {
    config: Config,
    stats: Arc<TrafficStats>,
}

impl TrafficClassifier {
    pub fn new(config: Config, stats: Arc<TrafficStats>) -> Self {
        Self {
            config,
            stats,
        }
    }

    pub fn start_capture(&self) -> Result<(), Box<dyn std::error::Error>> {
        let device = Device::lookup()?
            .ok_or("No network device found")?;
        
        let mut cap = Capture::from_device(device)?
            .promisc(true)
            .snaplen(65535)
            .timeout(1000)
            .open()?;
        
        if let Some(ref filter) = self.config.filter {
            cap.filter(filter, true)?;
        }
        
        println!("Starting traffic capture for monitoring (no filtering)");
        
        while crate::RUNNING.load(std::sync::atomic::Ordering::SeqCst) {
            match cap.next_packet() {
                Ok(packet) => {
                    self.process_packet(&packet);
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => eprintln!("Error reading packet: {}", e),
            }
        }
        
        Ok(())
    }
    
    fn process_packet(&self, packet: &pcap::Packet) {
        if packet.data.len() < 34 { // 以太網頭 + IP 頭
            return;
        }
        
        // 簡單的流量分類和統計
        let service = self.classify_packet(&packet.data);
        let packet_size = packet.data.len() as u64;
        
        self.stats.add_traffic(&service, packet_size, 1);
    }
    
    fn classify_packet(&self, data: &[u8]) -> String {
        // 簡單的基於目標端口的分類
        if data.len() < 36 {
            return "unknown".to_string();
        }
        
        // 提取目標端口（TCP/UDP 頭中的第2-3字節）
        let dport = u16::from_be_bytes([data[34], data[35]]);
        
        match dport {
            80 | 8080 => "http".to_string(),
            443 => "https".to_string(),
            53 => "dns".to_string(),
            1935 => "rtmp".to_string(),
            3478 | 5349 => "webrtc".to_string(),
            _ => {
                if dport >= 8000 && dport <= 9000 {
                    "streaming".to_string()
                } else {
                    "other".to_string()
                }
            }
        }
    }
}