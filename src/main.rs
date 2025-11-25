fn report_stats(stats: Arc<TrafficStats>, nft_classifier: NftablesClassifier, interval: u64) {
    while RUNNING.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(interval));
        
        // 從 nftables 獲取統計
        match nft_classifier.get_traffic_stats() {
            Ok(nft_stats) => {
                println!("=== NFTables Traffic Statistics ===");
                for (service, packets) in nft_stats {
                    println!("{}: {} packets", service, packets);
                }
            }
            Err(e) => eprintln!("Failed to get nftables stats: {}", e),
        }
        
        // 從內部統計獲取詳細數據
        let internal_stats = stats.get_detailed_stats();
        if !internal_stats.is_empty() {
            println!("=== Internal Traffic Statistics ===");
            for (service, traffic_data) in internal_stats {
                let duration = traffic_data.last_seen.duration_since(traffic_data.first_seen)
                    .unwrap_or(Duration::from_secs(1));
                let bytes_per_sec = traffic_data.bytes as f64 / duration.as_secs_f64();
                
                println!("{}:", service);
                println!("  Bytes: {:.2} MB", traffic_data.bytes as f64 / 1024.0 / 1024.0);
                println!("  Packets: {}", traffic_data.packets);
                println!("  Rate: {:.2} KB/s", bytes_per_sec / 1024.0);
                println!("  Duration: {:.2} seconds", duration.as_secs_f64());
            }
        }
        
        println!("=====================================");
    }
}