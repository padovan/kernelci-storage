use tokio::time::Duration;
use std::time::SystemTime;
use std::fs;
use fs2;

struct Files {
    file: String,
    last_update: SystemTime,
}

async fn read_files() -> Vec<Files> {
    let mut files = Vec::new();
    let paths = fs::read_dir(".");
    match paths {
        Ok(paths) => {
            for path in paths {
                let path = path.unwrap().path();
                let file = path.to_str().unwrap().to_string();
                let metadata = fs::metadata(&file).unwrap();
                let last_update = metadata.modified().unwrap();
                files.push(Files { file, last_update });
            }
            files
        }
        Err(_) => {
            println!("Error reading files");
            Vec::new()
        }
    }
}

async fn freediskspace_percent(cache_dir: String) -> u64 {
    let total_r = fs2::total_space(&cache_dir);
    let free_r = fs2::available_space(&cache_dir);
    let total = match total_r {
        Ok(total) => total as f64,
        Err(_) => {
            println!("Error getting total space");
            return 0;
        }
    };
    let free = match free_r {
        Ok(free) => free as f64,
        Err(_) => {
            println!("Error getting free space");
            return 0;
        }
    };

    let percent = (free / total) * 100.0;
    percent as u64
}

pub async fn cache_loop(cache_dir: &str) {
    loop {
        let free_space = freediskspace_percent(cache_dir.to_string()).await;
        if free_space < 10 {
            println!("Low disk space: {}%", free_space);
        } else {
            println!("Free disk space: {}%", free_space);
        }
        // sleep for 10 seconds
        tokio::time::sleep(Duration::from_secs(10)).await;       
    }
}        
