# php-scanner

Rust-based scanner for PHP projects that detects malicious files using **YARA rules + entropy analysis**. It can catch:

- Known webshells and droppers (via YARA signatures)
- Obfuscated or encoded payloads (via Shannon entropy)
- Custom rules you provide as `.yar` files

## Features

- Recursive scan of a project directory (WordPress, custom PHP apps, etc.)
- YARA-based detection (droppers, webshells, obfuscation)
- Entropy-based detection for unknown/obfuscated blobs
- Parallel scanning using all CPU cores
- Colorful terminal report or JSON output
- Built-in rules embedded into the binary, with optional external rules override

## Rules and Embedding

The scanner loads rules in this order:

1. If the directory passed via --rules (or ./rules by default) **exists**, it loads all .yar files from there.
    
2. If the directory does **not** exist, it falls back to **embedded rules** compiled into the binary:
    * droppers.yar
    * webshells.yar
    * obfuscation.yar
        
This means:

* The binary alone is enough to use the scanner (embedded rules).
* If you provide your own .yar files in a directory, they are used instead.

## Scoring Model

Each scanned file gets a **score** based on:

* YARA rule hits
* YARA string hits
* Shannon entropy of the file content
    
Currently:

* Each matched rule: **+5**
* Each matched string: **+2**
    
Entropy bonuses:

* Entropy > 6.0 → **+10**
* Entropy 5.5–6.0 → **+6**
* Entropy 5.0–5.5 → **+3**
    
Risk levels:

* score == 0 → file ignored
* 1–14 → **Suspicious**
* \>= 15 → **Critical**

## Usage

### Basic scan

```
php-scanner --path /var/www/html
```

### Use a custom rules directory

```
php-scanner --path /var/www/html --rules ./rules
```

### JSON output

```
php-scanner --path ./test-project --json > report.json
```

### Adjust minimum score to report

```
php-scanner --path ./test-project --min-score 10
```

### CLI options

```
php-scanner --help
```

## Example Output

```
[CRITICAL] score: 20 | entropy: 5.36 | /path/to/78sdfsdf.php
  ▶ PHP_Dropper_FileWrite_Traversal
    └ $write
    └ $traversal
    └ $cmd
    └ $fwrite
    └ $error_hide
    └ $self_delete

[SUSPICIOUS] score: 9 | entropy: 4.88 | /path/to/webshell1.php
  ▶ PHP_Webshell_Interactive_GET
    └ $get_cmd
    └ $exec4

[CRITICAL] score: 19 | entropy: 5.42 | /path/to/webshell2.php
  ▶ PHP_Webshell_Interactive_GET
  ▶ PHP_Obfuscation_Eval_Encoded
    └ $get_cmd
    └ $exec4
    └ $s1

[SUSPICIOUS] score: 6 | entropy: 5.56 | /path/to/obfuscated_blob.php
  ⚠ High entropy detected (5.56) — possible obfuscated blob

Total: 4 file(s) flagged.
```