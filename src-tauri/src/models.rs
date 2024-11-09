use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub devices: Vec<Device>,
    total_cves: CveCount,
}

impl ScanResult {
    pub fn new(devices: Vec<Device>) -> Self {
        let (low_risk, medium_risk, high_risk) =
            devices
                .iter()
                .fold((0, 0, 0), |(l, m, h), e| match e.risk_level {
                    RiskLevel::Low => (l + 1, m, h),
                    RiskLevel::Medium => (l, m + 1, h),
                    RiskLevel::High => (l, m, h + 1),
                });

        Self {
            devices,
            total_cves: CveCount {
                low_risk,
                medium_risk,
                high_risk,
            },
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Device {
    id: i16,
    name: String,
    ip: String,
    pub risk_level: RiskLevel,
    pub vulnerabilities: Vec<Vulnerability>,
}

impl Device {
    pub fn new(id: i16, name: String, ip: String, vulnerabilities: Vec<Vulnerability>) -> Self {
        let mut risk_level = RiskLevel::Low;
        for lvl in vulnerabilities.iter().map(|x| &x.risk_level) {
            if let RiskLevel::High = lvl {
                risk_level = RiskLevel::High;
                break;
            } else if let RiskLevel::Medium = lvl {
                risk_level = RiskLevel::Medium;
            }
        }

        Self {
            id,
            name,
            ip,
            risk_level,
            vulnerabilities,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Vulnerability {
    id: i16,
    pub name: String,
    pub description: String,
    risk_level: RiskLevel,
    pub cve_score: f32,
}

impl Vulnerability {
    pub fn new(id: i16, name: String, cve_score: f32) -> Self {
        let risk_level = match cve_score {
            c if c <= 4.0 => RiskLevel::Low,
            c if c <= 7.0 => RiskLevel::Medium,
            _ => RiskLevel::High,
        };

        Self {
            id,
            name,
            description: "".to_string(),
            risk_level,
            cve_score,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CveCount {
    low_risk: usize,
    medium_risk: usize,
    high_risk: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}
