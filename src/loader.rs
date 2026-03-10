use std::fs;
use std::path::Path;
use yara::Compiler;

pub fn load_rules(rules_dir: &str) -> yara::Rules {
    let mut compiler = Compiler::new().unwrap();

    if Path::new(rules_dir).exists() {
        for entry in fs::read_dir(rules_dir).unwrap().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("yar") {
                compiler = compiler.add_rules_file(&path).unwrap();
            }
        }
    } else {
        compiler = compiler
            .add_rules_str(include_str!("../rules/droppers.yar"))
            .unwrap();
        compiler = compiler
            .add_rules_str(include_str!("../rules/webshells.yar"))
            .unwrap();
        compiler = compiler
            .add_rules_str(include_str!("../rules/obfuscation.yar"))
            .unwrap();
    }

    compiler.compile_rules().unwrap()
}
