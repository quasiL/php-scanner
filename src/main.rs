//apt install libyara-dev
//apt install build-essential
//apt install libclang-dev clang

use clap::Parser;
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressStyle};
use rayon::prelude::*;
use walkdir::WalkDir;

mod loader;
mod report;
mod scanner;

#[derive(Parser)]
#[command(
    name = "php-scanner",
    about = "PHP malware scanner using YARA + entropy"
)]
struct Cli {
    #[arg(short, long, default_value = ".")]
    path: String,

    #[arg(short, long, default_value = "./rules")]
    rules: String,

    #[arg(short, long)]
    json: bool,

    #[arg(short, long, default_value_t = 5)]
    min_score: u32,
}

fn main() {
    let cli = Cli::parse();
    let extensions = ["php", "phtml", "php5", "php7", "phar", "js"];

    let rules = loader::load_rules(&cli.rules);

    let files: Vec<String> = WalkDir::new(&cli.path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .filter(|e| {
            let ext = e.path().extension().and_then(|x| x.to_str()).unwrap_or("");
            extensions.contains(&ext)
        })
        .map(|e| e.path().to_string_lossy().to_string())
        .collect();

    let pb = ProgressBar::new(files.len() as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%)",
        )
        .unwrap()
        .progress_chars("##-"),
    );
    pb.set_message("Scanning files");

    let results: Vec<scanner::ScanResult> = files
        .par_iter()
        .progress_with(pb)
        .filter_map(|path| scanner::scan_file(path, &rules))
        .filter(|r| r.score >= cli.min_score)
        .collect();

    if cli.json {
        report::print_json(&results);
    } else {
        report::print_terminal(&results);
    }
}
