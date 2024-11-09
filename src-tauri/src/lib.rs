use anyhow::{anyhow, Result};
use dotenv::dotenv;
use get_if_addrs::get_if_addrs;
use get_if_addrs::IfAddr;
use models::ScanResult;
use std::net::IpAddr;
use std::net::Ipv4Addr;

mod gemini;
mod models;
mod scan;

#[macro_use]
extern crate tracing;

fn get_ip() -> Result<String> {
    let ifaces = get_if_addrs()?;

    for iface in ifaces {
        if iface.is_loopback() {
            continue;
        }

        if let IpAddr::V4(ip_addr) = iface.ip() {
            if let IfAddr::V4(ifv4) = iface.addr {
                let prefix_len = count_ones(&ifv4.netmask);

                let ip = format!("{}/{}", ip_addr, prefix_len);
                info!(ip = &ip, "Found ip");
                return Ok(ip);
            }
        }
    }

    Err(anyhow!("No main IPv4 address found"))
}

fn count_ones(mask: &Ipv4Addr) -> u32 {
    mask.octets().iter().map(|octet| octet.count_ones()).sum()
}

// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
async fn scan() -> Result<ScanResult, String> {
    match scan::scan(get_ip().map_err(|e| e.to_string())?).await {
        Ok(results) => {
            let mut res: ScanResult = results.into();

            for dev in res.devices.iter_mut() {
                for vuln in dev.vulnerabilities.iter_mut() {
                    match gemini::explain_cve(vuln.name.clone()).await {
                        Ok(desc) => vuln.description = desc,
                        Err(err) => {
                            vuln.description = format!("Gemini failed: {}", err.to_string())
                        }
                    }
                }
            }

            Ok(res)
        }
        Err(err) => Err(err.to_string()),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    dotenv().unwrap();
    tracing_subscriber::fmt().init();
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![scan])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
