use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use std::collections::HashMap;

// 定義 nftables 模塊
mod nftables {
    use std::collections::HashMap;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ClassifiedTraffic {
        pub bytes: u64,
        pub packets: u64,
        pub protocol: String,
        pub source_ip: String,
        pub destination_ip: String,
        pub source_port: Option<u16>,
        pub destination_port: Option<u16>,
        pub application: String,
        pub category: TrafficCategory,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
    pub enum TrafficCategory {
        Web,
        Database,
        Streaming,
        FileTransfer,
        Gaming,
        Voip,
        Malicious,
        Unknown,
    }

    #[derive(Debug, Clone)]
    pub struct NftablesClassifier {
        rules: HashMap<String, TrafficCategory>,
        application_map: HashMap<(u16, String), String>,
        #[allow(dead_code)]
        malicious_ips: Vec<String>,
        cache: HashMap<String, ClassifiedTraffic>,
    }

    impl NftablesClassifier {
        pub fn new() -> Self {
            let mut classifier = Self {
                rules: HashMap::new(),
                application_map: HashMap::new(),
                malicious_ips: Vec::new(),
                cache: HashMap::new(),
            };
            
            classifier.initialize_application_map();
            classifier.initialize_rules();
            classifier
        }
        
        fn initialize_application_map(&mut self) {
            // Web 流量
            self.application_map.insert((80, "tcp".to_string()), "HTTP".to_string());
            self.application_map.insert((443, "tcp".to_string()), "HTTPS".to_string());
            self.application_map.insert((8080, "tcp".to_string()), "HTTP-Alt".to_string());
            
            // 資料庫
            self.application_map.insert((3306, "tcp".to_string()), "MySQL".to_string());
            self.application_map.insert((5432, "tcp".to_string()), "PostgreSQL".to_string());
            self.application_map.insert((27017, "tcp".to_string()), "MongoDB".to_string());
            
            // DNS
            self.application_map.insert((53, "udp".to_string()), "DNS".to_string());
            self.application_map.insert((53, "tcp".to_string()), "DNS".to_string());
        }
        
        fn initialize_rules(&mut self) {
            self.rules.insert("http".to_string(), TrafficCategory::Web);
            self.rules.insert("https".to_string(), TrafficCategory::Web);
            self.rules.insert("mysql".to_string(), TrafficCategory::Database);
            self.rules.insert("postgresql".to_string(), TrafficCategory::Database);
        }
        
        pub fn classify_traffic(
            &mut self,
            source_ip: &str,
            destination_ip: &str,
            source_port: Option<u16>,
            destination_port: Option<u16>,
            protocol: &str,
            bytes: u64,
        ) -> ClassifiedTraffic {
            let cache_key = format!(
                "{}-{}-{}-{}-{}",
                source_ip, destination_ip,
                source_port.unwrap_or(0),
                destination_port.unwrap_or(0),
                protocol
            );
            
            if let Some(cached) = self.cache.get(&cache_key) {
                return cached.clone();
            }
            
            let application = self.detect_application(destination_port, protocol);
            let category = self.detect_category(&application, destination_port, protocol);
            
            let classified = ClassifiedTraffic {
                bytes,
                packets: 1,
                protocol: protocol.to_string(),
                source_ip: source_ip.to_string(),
                destination_ip: destination_ip.to_string(),
                source_port,
                destination_port,
                application: application.clone(),
                category,
            };
            
            self.cache.insert(cache_key, classified.clone());
            classified
        }
        
        fn detect_application(&self, port: Option<u16>, protocol: &str) -> String {
            if let Some(port_num) = port {
                if let Some(app) = self.application_map.get(&(port_num, protocol.to_string())) {
                    return app.clone();
                }
                
                match port_num {
                    20..=21 => "FTP".to_string(),
                    22 => "SSH".to_string(),
                    25 => "SMTP".to_string(),
                    53 => "DNS".to_string(),
                    80 => "HTTP".to_string(),
                    443 => "HTTPS".to_string(),
                    3306 => "MySQL".to_string(),
                    5432 => "PostgreSQL".to_string(),
                    _ => "Unknown".to_string(),
                }
            } else {
                "Unknown".to_string()
            }
        }
        
        fn detect_category(&self, application: &str, port: Option<u16>, _protocol: &str) -> TrafficCategory {
            let app_lower = application.to_lowercase();
            
            if app_lower.contains("http") || app_lower.contains("web") {
                return TrafficCategory::Web;
            }
            
            if app_lower.contains("mysql") || app_lower.contains("postgres") {
                return TrafficCategory::Database;
            }
            
            if let Some(port_num) = port {
                match port_num {
                    80 | 443 | 8080 | 8443 => TrafficCategory::Web,
                    3306 | 5432 | 27017 => TrafficCategory::Database,
                    21 | 22 => TrafficCategory::FileTransfer,
                    _ => TrafficCategory::Unknown,
                }
            } else {
                TrafficCategory::Unknown
            }
        }
        
        #[allow(dead_code)]
        pub fn add_malicious_ip(&mut self, ip: &str) {
            if !self.malicious_ips.contains(&ip.to_string()) {
                self.malicious_ips.push(ip.to_string());
            }
        }
        
        pub fn get_traffic_summary(&self) -> HashMap<TrafficCategory, u64> {
            let mut summary = HashMap::new();
            
            for traffic in self.cache.values() {
                *summary.entry(traffic.category.clone()).or_insert(0) += traffic.bytes;
            }
            
            summary
        }
        
        #[allow(dead_code)]
        pub fn clear_cache(&mut self) {
            self.cache.clear();
        }
    }

    impl Default for NftablesClassifier {
        fn default() -> Self {
            Self::new()
        }
    }
}

// 使用模塊中的類型
use nftables::{NftablesClassifier, TrafficCategory, ClassifiedTraffic};

// 定義 TrafficStats 結構體
#[derive(Debug, Clone)]
struct TrafficStats {
    bytes_received: u64,
    bytes_sent: u64,
    packets_received: u64,
    packets_sent: u64,
    classified_traffic: HashMap<TrafficCategory, u64>,
}

impl TrafficStats {
    fn new() -> Self {
        Self {
            bytes_received: 0,
            bytes_sent: 0,
            packets_received: 0,
            packets_sent: 0,
            classified_traffic: HashMap::new(),
        }
    }
    
    fn update(&mut self, classified: &ClassifiedTraffic) {
        // 簡單假設:根據端口判斷是接收還是發送
        if classified.destination_port == Some(80) || classified.destination_port == Some(443) {
            self.bytes_received += classified.bytes;
            self.packets_received += classified.packets;
        } else {
            self.bytes_sent += classified.bytes;
            self.packets_sent += classified.packets;
        }
        
        // 更新分類統計
        *self.classified_traffic.entry(classified.category.clone()).or_insert(0) += classified.bytes;
    }
    
    fn display_summary(&self) {
        println!("=== 流量統計 ===");
        println!("接收: {} 字節, {} 包包", self.bytes_received, self.packets_received);
        println!("發送: {} 字節, {} 包包", self.bytes_sent, self.packets_sent);
        println!("總計: {} 字節", self.bytes_received + self.bytes_sent);
        
        println!("\n=== 流量分類 ===");
        for (category, bytes) in &self.classified_traffic {
            println!("{:?}: {} 字節", category, bytes);
        }
        println!("================\n");
    }
}

// 信號處理
fn setup_signal_handler(running: Arc<AtomicBool>) {
    ctrlc::set_handler(move || {
        println!("\n收到停止信號,正在關閉...");
        running.store(false, Ordering::SeqCst);
    }).expect("設置信號處理器失敗");
}

// 統計報告函數
fn report_stats(
    stats: Arc<std::sync::Mutex<TrafficStats>>, 
    nft_classifier: Arc<std::sync::Mutex<NftablesClassifier>>, 
    interval: u64,
    running: Arc<AtomicBool>
) {
    while running.load(Ordering::SeqCst) {
        // 顯示統計信息
        {
            let stats_guard = stats.lock().unwrap();
            stats_guard.display_summary();
        }
        
        // 顯示分類器統計
        {
            let classifier_guard = nft_classifier.lock().unwrap();
            let summary = classifier_guard.get_traffic_summary();
            if !summary.is_empty() {
                println!("=== 分類器統計 ===");
                for (category, bytes) in summary {
                    println!("{:?}: {} 字節", category, bytes);
                }
                println!("==================\n");
            }
        }
        
        thread::sleep(Duration::from_secs(interval));
    }
}

// 模擬流量捕獲的函數
fn capture_traffic(
    stats: Arc<std::sync::Mutex<TrafficStats>>, 
    classifier: Arc<std::sync::Mutex<NftablesClassifier>>,
    running: Arc<AtomicBool>
) {
    let mut packet_count = 0;
    
    while running.load(Ordering::SeqCst) {
        packet_count += 1;
        
        // 模擬一些網絡流量
        let sample_traffic = vec![
            ("192.168.1.100", "93.184.216.34", Some(54321), Some(80), "tcp", 1500), // HTTP
            ("192.168.1.100", "93.184.216.34", Some(54322), Some(443), "tcp", 2500), // HTTPS
            ("192.168.1.100", "192.168.1.200", Some(54323), Some(3306), "tcp", 1200), // MySQL
            ("192.168.1.100", "8.8.8.8", Some(54324), Some(53), "udp", 512), // DNS
        ];
        
        for (src_ip, dst_ip, src_port, dst_port, protocol, bytes) in sample_traffic {
            let classified = {
                let mut classifier_guard = classifier.lock().unwrap();
                classifier_guard.classify_traffic(src_ip, dst_ip, src_port, dst_port, protocol, bytes)
            };
            
            {
                let mut stats_guard = stats.lock().unwrap();
                stats_guard.update(&classified);
            }
            
            if packet_count % 10 == 0 {
                println!("處理包包 #{}: {}:{} -> {}:{} [{}] - {} 字節", 
                    packet_count, src_ip, src_port.unwrap_or(0), 
                    dst_ip, dst_port.unwrap_or(0), protocol, bytes);
            }
        }
        
        thread::sleep(Duration::from_millis(500));
    }
}

fn main() {
    println!("🚀 TrafficMon 流量監控工具啟動中...");
    
    // 初始化統計數據
    let stats = Arc::new(std::sync::Mutex::new(TrafficStats::new()));
    let classifier = Arc::new(std::sync::Mutex::new(NftablesClassifier::new()));
    
    // 創建全局運行狀態
    let running = Arc::new(AtomicBool::new(true));
    
    // 設置信號處理
    setup_signal_handler(Arc::clone(&running));
    
    // 克隆 Arc 用於不同線程
    let stats_capture = Arc::clone(&stats);
    let classifier_capture = Arc::clone(&classifier);
    let running_capture = Arc::clone(&running);
    
    let stats_report = Arc::clone(&stats);
    let classifier_report = Arc::clone(&classifier);
    let running_report = Arc::clone(&running);
    
    // 啟動流量捕獲線程
    let capture_handle = thread::spawn(move || {
        capture_traffic(stats_capture, classifier_capture, running_capture);
    });
    
    // 啟動統計報告線程
    let report_handle = thread::spawn(move || {
        report_stats(stats_report, classifier_report, 5, running_report);
    });
    
    println!("📊 流量監控運行中... 按 Ctrl+C 停止");
    
    // 等待線程結束
    capture_handle.join().unwrap();
    report_handle.join().unwrap();
    
    println!("👋 TrafficMon 已正常關閉");
}