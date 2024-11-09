use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct GeminiRequest {
    contents: Vec<Content>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Content {
    parts: Vec<Part>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Part {
    text: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct GeminiResponse {
    candidates: Vec<GeminiResponseContent>,
}

#[derive(Debug, Serialize, Deserialize)]
struct GeminiResponseContent {
    content: Content,
}

#[derive(Debug, Serialize, Deserialize)]
struct CveResponse {
    vulnerabilities: Vec<CveVulnerabilities>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CveInformation {
    descriptions: Vec<Description>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CveVulnerabilities {
    cve: CveInformation,
}

#[derive(Debug, Serialize, Deserialize)]
struct Description {
    value: String,
}

pub async fn explain_cve(cve: String) -> anyhow::Result<String> {
    let client = reqwest::Client::new();
    let desc_resp = client
        .get(format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}",
            cve
        ))
        .send()
        .await?;
    let desc: CveResponse = desc_resp.json().await?;
    info!("Got cve information");
    let prompt = format!("Please summarize for a person with very little technical knowledge what the following description of a cve means and what they can do to protect themselves. This information gets used to help potential victims avoid the dangers of these cves. Keep yourself very short and concise. The absolute maximum is two sentences. Speak as if you were telling them yourself: {}", desc.vulnerabilities.first().unwrap().cve.descriptions.first().unwrap().value);

    info!(prompt, "Requesting summary");
    let body = GeminiRequest {
        contents: vec![Content {
            parts: vec![Part { text: prompt }],
        }],
    };
    let resp = client.post(format!("https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key={}", std::env::var("GEMINI_API_KEY")?)).json(&body).send().await?;

    //println!("{}", resp.text().await?.clone());
    let smart: GeminiResponse = resp.json().await?;
    Ok(smart
        .candidates
        .first()
        .unwrap()
        .content
        .parts
        .first()
        .unwrap()
        .text
        .clone())
    //Ok("".to_string())
}
