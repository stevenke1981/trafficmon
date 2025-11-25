use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, Duration};
use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
pub struct TrafficData {
    pub bytes: u64,
    pub packets: u64,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
}

#[derive(Debug)]
pub struct TrafficStats {
    data: Mutex<StatsData>,
    retention_period: Duration,
}

#[derive(Debug)]
struct StatsData {
    current: HashMap<String, TrafficData>,
    history: Vec<(SystemTime, HashMap<String, TrafficData>)>,
}

impl TrafficStats {
    pub fn new() -> Self {
        Self {
            data: Mutex::new(StatsData {
                current: HashMap::new(),
                history: Vec::new(),
            }),
            retention_period: Duration::from_secs(3600), // 保留1小時歷史數據
        }
    }
    
    pub fn add_traffic(&self, service: &str, bytes: u64, packets: u64) {
        let mut data = self.data.lock().unwrap();
        let now = SystemTime::now();
        
        let traffic_data = data.current.entry(service.to_string()).or_insert_with(|| TrafficData {
            bytes: 0,
            packets: 0,
            first_seen: now,
            last_seen: now,
        });
        
        traffic_data.bytes += bytes;
        traffic_data.packets += packets;
        traffic_data.last_seen = now;
    }
    
    pub fn get_stats(&self) -> HashMap<String, (u64, u64)> {
        let mut data = self.data.lock().unwrap();
        let now = SystemTime::now();
        
        // 保存當前統計到歷史記錄
        if !data.current.is_empty() {
            data.history.push((now, data.current.clone()));
            data.current.clear();
        }
        
        // 清理過期數據
        self.clean_old_data(&mut data);
        
        // 合併歷史數據並返回簡化格式
        self.merge_history(&data.history)
    }
    
    pub fn get_detailed_stats(&self) -> HashMap<String, TrafficData> {
        let mut data = self.data.lock().unwrap();
        let now = SystemTime::now();
        
        // 保存當前統計到歷史記錄
        if !data.current.is_empty() {
            data.history.push((now, data.current.clone()));
            data.current.clear();
        }
        
        // 清理過期數據
        self.clean_old_data(&mut data);
        
        // 合併歷史數據
        let mut merged = HashMap::new();
        for (_, stats) in &data.history {
            for (service, traffic_data) in stats {
                let entry = merged.entry(service.clone()).or_insert_with(|| TrafficData {
                    bytes: 0,
                    packets: 0,
                    first_seen: traffic_data.first_seen,
                    last_seen: traffic_data.last_seen,
                });
                
                entry.bytes += traffic_data.bytes;
                entry.packets += traffic_data.packets;
                
                // 更新時間範圍
                if traffic_data.first_seen < entry.first_seen {
                    entry.first_seen = traffic_data.first_seen;
                }
                if traffic_data.last_seen > entry.last_seen {
                    entry.last_seen = traffic_data.last_seen;
                }
            }
        }
        
        merged
    }
    
    fn clean_old_data(&self, data: &mut StatsData) {
        let now = SystemTime::now();
        data.history.retain(|(timestamp, _)| {
            now.duration_since(*timestamp)
                .map(|dur| dur < self.retention_period)
                .unwrap_or(false)
        });
    }
    
    fn merge_history(&self, history: &[(SystemTime, HashMap<String, TrafficData>)]) -> HashMap<String, (u64, u64)> {
        let mut merged = HashMap::new();
        
        for (_, stats) in history {
            for (service, traffic_data) in stats {
                let entry = merged.entry(service.clone()).or_insert((0, 0));
                entry.0 += traffic_data.bytes;
                entry.1 += traffic_data.packets;
            }
        }
        
        merged
    }
    
    pub fn reset_stats(&self) {
        let mut data = self.data.lock().unwrap();
        data.current.clear();
        data.history.clear();
    }
    
    pub fn get_service_stats(&self, service: &str) -> Option<TrafficData> {
        let data = self.data.lock().unwrap();
        let mut result = None;
        
        // 檢查當前數據
        if let Some(current) = data.current.get(service) {
            result = Some(current.clone());
        }
        
        // 合併歷史數據
        for (_, stats) in &data.history {
            if let Some(historical) = stats.get(service) {
                if let Some(ref mut res) = result {
                    res.bytes += historical.bytes;
                    res.packets += historical.packets;
                    if historical.first_seen < res.first_seen {
                        res.first_seen = historical.first_seen;
                    }
                    if historical.last_seen > res.last_seen {
                        res.last_seen = historical.last_seen;
                    }
                } else {
                    result = Some(historical.clone());
                }
            }
        }
        
        result
    }
}

impl Default for TrafficStats {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for TrafficData {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            packets: self.packets,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_traffic_stats() {
        let stats = TrafficStats::new();
        
        // 添加一些數據
        stats.add_traffic("netflix", 1024, 10);
        stats.add_traffic("youtube", 2048, 20);
        stats.add_traffic("netflix", 512, 5);
        
        // 檢查統計
        let result = stats.get_stats();
        assert_eq!(result.get("netflix").unwrap().0, 1536); // 1024 + 512
        assert_eq!(result.get("netflix").unwrap().1, 15);   // 10 + 5
        assert_eq!(result.get("youtube").unwrap().0, 2048);
        assert_eq!(result.get("youtube").unwrap().1, 20);
    }
    
    #[test]
    fn test_reset_stats() {
        let stats = TrafficStats::new();
        
        stats.add_traffic("netflix", 1024, 10);
        stats.reset_stats();
        
        let result = stats.get_stats();
        assert!(result.is_empty());
    }
}