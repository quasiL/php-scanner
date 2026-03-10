use crate::scanner::{RiskLevel, ScanResult};
use colored::*;

pub fn print_terminal(results: &[ScanResult]) {
    if results.is_empty() {
        println!("{}", "No suspicious files found.".green().bold());
        return;
    }

    for r in results {
        let label = match r.risk {
            RiskLevel::Critical => "CRITICAL".red().bold(),
            RiskLevel::Suspicious => "SUSPICIOUS".yellow().bold(),
        };

        println!(
            "\n[{}] score: {} | entropy: {:.2} | {}",
            label,
            r.score,
            r.entropy,
            r.path.white().bold()
        );

        for rule in &r.rule_hits {
            println!("  {} {}", "▶".cyan(), rule.cyan());
        }
        for s in &r.string_hits {
            println!("    {} {}", "└".dimmed(), s.dimmed());
        }

        if r.entropy > 5.5 {
            println!(
                "  {} High entropy detected ({:.2}) — possible obfuscated blob",
                "⚠".yellow(),
                r.entropy
            );
        }
    }

    println!("\n{} {} file(s) flagged.", "Total:".bold(), results.len());
}

pub fn print_json(results: &[ScanResult]) {
    println!("{}", serde_json::to_string_pretty(results).unwrap());
}
