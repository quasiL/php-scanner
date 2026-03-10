use serde::Serialize;
use std::fs;
use yara::Rules;

#[derive(Debug, Serialize)]
pub enum RiskLevel {
    Suspicious,
    Critical,
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub path: String,
    pub rule_hits: Vec<String>,
    pub string_hits: Vec<String>,
    pub entropy: f64,
    pub score: u32,
    pub risk: RiskLevel,
}

pub fn shannon_entropy(data: &[u8]) -> f64 {
    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

pub fn scan_file(path: &str, rules: &Rules) -> Option<ScanResult> {
    let content = fs::read(path).ok()?;
    if content.is_empty() {
        return None;
    }

    let entropy = shannon_entropy(&content);
    let matches = rules.scan_mem(&content, 5).ok()?;
    if matches.is_empty() && entropy < 5.0 {
        return None;
    }

    let mut rule_hits: Vec<String> = vec![];
    let mut string_hits: Vec<String> = vec![];

    for m in &matches {
        rule_hits.push(m.identifier.to_string());
        for s in &m.strings {
            if !s.matches.is_empty() {
                string_hits.push(s.identifier.to_string());
            }
        }
    }

    let mut score: u32 = 0;
    if !rule_hits.is_empty() {
        score += rule_hits.len() as u32 * 5;
        score += string_hits.len() as u32 * 2;
    }

    if entropy > 6.0 {
        score += 10;
    } else if entropy > 5.5 {
        score += 6;
    } else if entropy > 5.0 {
        score += 3;
    }

    if score == 0 {
        return None;
    }

    let risk = if score >= 15 {
        RiskLevel::Critical
    } else {
        RiskLevel::Suspicious
    };

    Some(ScanResult {
        path: path.to_string(),
        rule_hits,
        string_hits,
        entropy,
        score,
        risk,
    })
}
