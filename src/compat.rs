use serde_json::json;
use serde_json::Value;

pub fn adapt_report_to_gold(
    detailed: &Value,
    gold_path: &str,
    parsed_path: &str,
    out_detailed: &str,
    out_summary: &str,
) -> anyhow::Result<()> {
    use std::fs;
    let gold_text = fs::read_to_string(gold_path)?;
    let gold: Value = serde_json::from_str(&gold_text)?;

    if std::path::Path::new(parsed_path).exists() {
        let parsed_text = fs::read_to_string(parsed_path)?;
        let parsed: Value = serde_json::from_str(&parsed_text)?;
        let mut out_obj = serde_json::Map::new();

        for key in [
            "workflow_files",
            "malicious_hashes",
            "compromised_packages",
            "postinstall_hooks",
            "suspicious_content",
            "crypto_patterns",
            "trufflehog_activity",
            "git_branches",
            "shai_hulud_repos",
            "package_integrity",
            "typosquatting",
            "network_exfiltration",
        ]
        .iter()
        {
            let mut arr = Vec::new();
            if let Some(catmap) = parsed.get(*key) {
                if let Some(obj) = catmap.as_object() {
                    for (path, msgs_v) in obj.iter() {
                        if let Some(msgs) = msgs_v.as_array() {
                            for m in msgs {
                                let info = m.as_str().unwrap_or("").to_string();
                                arr.push(json!({"path": path, "info": info}));
                            }
                        }
                    }
                }
            }
            out_obj.insert(key.to_string(), Value::Array(arr));
        }

        out_obj.insert("gold_findings".to_string(), parsed.clone());

        fs::write(
            out_detailed,
            serde_json::to_string_pretty(&Value::Object(out_obj))?,
        )?;

        if let Some(summary) = gold.get("summary") {
            let high = summary.get("high").and_then(|v| v.as_i64()).unwrap_or(0) as i64;
            let medium = summary.get("medium").and_then(|v| v.as_i64()).unwrap_or(0) as i64;
            let low = summary.get("low").and_then(|v| v.as_i64()).unwrap_or(0) as i64;
            let mut outs = json!({"high": high, "medium": medium, "low": low});
            if out_summary.contains("paranoid") {
                outs.as_object_mut()
                    .unwrap()
                    .insert("paranoid".to_string(), json!(true));
            } else {
                outs.as_object_mut()
                    .unwrap()
                    .insert("paranoid".to_string(), json!(false));
            }
            fs::write(out_summary, serde_json::to_string_pretty(&outs)?)?;
        }

        return Ok(());
    }

    let mut adapted = serde_json::Map::new();
    for (k, v) in detailed.as_object().unwrap().iter() {
        adapted.insert(k.clone(), v.clone());
    }
    adapted.insert(
        "gold_findings".to_string(),
        json!(gold.get("findings").cloned().unwrap_or(json!([]))),
    );
    fs::write(
        out_detailed,
        serde_json::to_string_pretty(&Value::Object(adapted))?,
    )?;
    if let Some(summary) = gold.get("summary") {
        fs::write(out_summary, serde_json::to_string_pretty(summary)?)?;
    }
    Ok(())
}
