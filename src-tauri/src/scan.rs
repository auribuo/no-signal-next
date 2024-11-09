#[cfg(feature = "demo")]
use crate::models::{Device, Vulnerability};
use anyhow::Result;
#[cfg(not(feature = "demo"))]
use futures_util::stream::StreamExt;
#[cfg(not(feature = "demo"))]
use scannerlib::{
    feed::{HashSumNameLoader, Update},
    models::{Port, PortRange, Scan, Target, VT},
    nasl::{nasl_std_functions, FSPluginLoader},
    scanner::ScanRunner,
    scheduling::{ExecutionPlaner, WaveExecutionPlan},
    storage::{ContextKey, Retriever},
};

use crate::models::ScanResult;

#[cfg(feature = "demo")]
pub async fn scan(cidr: String) -> Result<Vec<scannerlib::models::Result>> {
    debug!(ip = cidr, "Scanning");
    Ok(vec![])
}

#[cfg(not(feature = "demo"))]
pub async fn scan(cidr: String) -> Result<Vec<scannerlib::models::Result>> {
    let vts_lib = include_str!("../vts.json");
    let vts: Vec<String> = serde_json::from_str(&vts_lib)?;
    let target = Target {
        hosts: vec![cidr],
        excluded_hosts: vec![],
        ports: vec![Port {
            protocol: None,
            range: vec![PortRange {
                start: 0,
                end: Some(65535),
            }],
        }],
        credentials: vec![],
        alive_test_ports: vec![Port {
            protocol: None,
            range: vec![PortRange {
                start: 0,
                end: Some(65535),
            }],
        }],
        alive_test_methods: vec![],
        reverse_lookup_unify: Some(true),
        reverse_lookup_only: Some(true),
    };
    let scan: Scan = Scan {
        scan_id: "scan0".to_string(),
        target,
        scan_preferences: vec![],
        vts: vts
            .iter()
            .map(|oid| VT {
                oid: oid.to_string(),
                parameters: vec![],
            })
            .collect::<Vec<_>>(),
    };

    let feed_path = "nasl";
    let storage = scannerlib::storage::DefaultDispatcher::new();
    info!(?feed_path, "Loading feed. This may take a while.");

    let nasl_loader = FSPluginLoader::new(feed_path);
    let verifier = HashSumNameLoader::sha256(&nasl_loader)?;
    let updater = Update::init("1", 5, &nasl_loader, &storage, verifier);
    updater.perform_update().await?;

    info!("Feed loaded");

    let scan_id = scan.scan_id.clone();

    info!("Creating scheduling plan");
    let schedule = storage
        .execution_plan::<WaveExecutionPlan>(&scan)
        .expect("expected to be schedulable");
    info!("Loading checks");
    let executor = nasl_std_functions();
    let runner: ScanRunner<(_, _)> =
        ScanRunner::new(&storage, &nasl_loader, &executor, schedule, &scan).unwrap();
    let mut results = Box::pin(runner.stream());
    let mut total: usize = 0;
    let mut skipped: usize = 0;
    while let Some(x) = results.next().await {
        match x {
            Ok(x) => {
                total += 1;
                let _span =
                    warn_span!("script_result", filename=x.filename, oid=x.oid, stage=%x.stage)
                        .entered();
                if x.has_succeeded() {
                    info!("success");
                    println!("{:?}", x);
                } else {
                    skipped += 1;
                    debug!(kind=?x.kind, "failed");
                }
            }
            Err(e) => {
                warn!(error=?e, "failed to execute script.");
            }
        }
    }

    let results = storage
        .results(&ContextKey::Scan(scan_id, None))?
        .collect::<Vec<_>>();
    info!(total, skipped, results = results.len(), "Ran tests");

    Ok(results)
}

#[cfg(feature = "demo")]
impl Into<ScanResult> for Vec<scannerlib::models::Result> {
    fn into(self) -> ScanResult {
        let res = ScanResult::new(vec![
            Device::new(
                0,
                "ROG-Strix G35".to_string(),
                "10.199.213.159".to_string(),
                vec![
                    Vulnerability::new(0, "CVE-2024-9936".to_string(), 6.5),
                    Vulnerability::new(1, "CVE-2021-43893".to_string(), 7.5),
                    Vulnerability::new(2, "CVE-2023-5716".to_string(), 9.8),
                ],
            ),
            Device::new(
                1,
                "LG Smart TV".to_string(),
                "10.199.213.170".to_string(),
                vec![Vulnerability::new(3, "CVE-2023-6317".to_string(), 7.2)],
            ),
            Device::new(
                2,
                "SmartFridgeX223".to_string(),
                "10.199.213.142".to_string(),
                vec![Vulnerability::new(4, "CVE-2024-41999".to_string(), 6.8)],
            ),
            Device::new(
                3,
                "NginxProxy".to_string(),
                "10.199.213.144".to_string(),
                vec![Vulnerability::new(5, "CVE-2024-24989".to_string(), 6.8)],
            ),
            Device::new(
                4,
                "Apache2".to_string(),
                "10.199.213.145".to_string(),
                vec![Vulnerability::new(6, "CVE-2012-0021".to_string(), 3.1)],
            ),
            Device::new(
                5,
                "Samsung Galaxy S7".to_string(),
                "10.199.213.33".to_string(),
                vec![
                    Vulnerability::new(7, "CVE-2024-34636".to_string(), 4.0),
                    Vulnerability::new(8, "CVE-2023-42482".to_string(), 4.7),
                ],
            ),
            Device::new(
                6,
                "TexasIntstruments SmartCalc".to_string(),
                "10.199.213.1".to_string(),
                vec![Vulnerability::new(9, "CVE-2021-34149".to_string(), 2.8)],
            ),
        ]);
        res
    }
}

#[cfg(not(feature = "demo"))]
impl Into<ScanResult> for Vec<scannerlib::models::Result> {
    fn into(self) -> ScanResult {
        todo!("Actually test vuln system")
    }
}
