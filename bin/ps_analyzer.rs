//! CLI for PowerShell command-line analysis using psexposed indicators.
//! Decodes -enc/-encodedcommand and optionally runs Sigma rules on decoded content.
//! See: https://www.powershell.exposed/ and https://github.com/avasero/psexposed

use anyhow::Result;
use clap::Parser;
use sigma_zero::ps_analyzer::PsAnalyzer;
use sigma_zero::ps_indicator::read_command_lines;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "shell-we-dance")]
#[command(about = "PowerShell command-line analysis: psexposed indicators, -enc decoding, Sigma on decoded content")]
#[command(version)]
struct Args {
    /// Path to directory containing psexposed indicator YAML files
    #[arg(short = 'r', long, value_name = "DIR")]
    indicators_dir: PathBuf,

    /// Path to directory containing Sigma rules (YAML); decoded -enc content is evaluated against these
    #[arg(long, value_name = "DIR")]
    sigma_rules_dir: Option<PathBuf>,

    /// Analyze a single command line (can be repeated)
    #[arg(short, long = "command", value_name = "CMD")]
    commands: Vec<String>,

    /// Read command lines from file (one per line)
    #[arg(short, long, value_name = "FILE")]
    file: Option<PathBuf>,

    /// Output format: text, json, or jsonl
    #[arg(long, default_value = "text")]
    format: String,

    /// Minimum total score to output (0 = output all)
    #[arg(long, default_value = "0")]
    min_score: f64,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.verbose {
        tracing_subscriber::fmt().with_max_level(tracing::Level::DEBUG).init();
    }

    let analyzer = match &args.sigma_rules_dir {
        Some(sigma_dir) => {
            let a = PsAnalyzer::from_dirs(&args.indicators_dir, sigma_dir)?;
            eprintln!(
                "Loaded {} indicators from {} and Sigma rules from {}",
                a.indicator_count(),
                args.indicators_dir.display(),
                sigma_dir.display()
            );
            a
        }
        None => {
            let (a, load_results) = PsAnalyzer::from_dir_with_errors(&args.indicators_dir)?;
            let ok_count = load_results.iter().filter(|(_, r)| r.is_ok()).count();
            let fail_count = load_results.iter().filter(|(_, r)| r.is_err()).count();
            eprintln!(
                "Loaded {} indicators from {} ({} rule files ok, {} failed)",
                a.indicator_count(),
                args.indicators_dir.display(),
                ok_count,
                fail_count
            );
            if args.verbose {
                for (name, res) in &load_results {
                    match res {
                        Ok(()) => eprintln!("  [ok]   {}", name),
                        Err(e) => eprintln!("  [FAIL] {} — {}", name, e),
                    }
                }
            } else if fail_count > 0 {
                for (name, res) in &load_results {
                    if let Err(e) = res {
                        eprintln!("  [FAIL] {} — {}", name, e);
                    }
                }
            }
            a
        }
    };

    let mut command_lines: Vec<String> = args.commands;
    if let Some(ref p) = args.file {
        let from_file = read_command_lines(Some(p))?;
        command_lines.extend(from_file);
    }
    if command_lines.is_empty() {
        let from_stdin = read_command_lines(None)?;
        command_lines.extend(from_stdin);
    }

    if command_lines.is_empty() {
        eprintln!("No command lines to analyze. Use -c/--command, -f/--file, or pipe/type on stdin.");
        std::process::exit(1);
    }

    let mut results: Vec<_> = command_lines
        .iter()
        .map(|cmd| analyzer.analyze(cmd))
        .collect();

    if args.min_score > 0.0 {
        results.retain(|r| r.total_score >= args.min_score);
    }

    match args.format.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&results)?);
        }
        "jsonl" => {
            for r in &results {
                println!("{}", serde_json::to_string(r)?);
            }
        }
        _ => {
            for (i, r) in results.iter().enumerate() {
                if i > 0 {
                    println!("---");
                }
                print_result_text(r);
            }
        }
    }

    Ok(())
}

fn print_result_text(r: &sigma_zero::ps_analyzer::PsAnalysisResult) {
    println!("Command: {}", r.command_line);
    println!("Suspicious: {} | Total score: {:.1}", r.is_suspicious, r.total_score);

    if let Some(ref dec) = r.decoded_content {
        println!("Decoded (-enc):");
        for line in dec.lines().take(20) {
            println!("  {}", line);
        }
        if dec.lines().count() > 20 {
            println!("  ... ({} more lines)", dec.lines().count() - 20);
        } else if !dec.contains('\n') && dec.len() > 80 {
            println!("  {}...", &dec[..77]);
        }
    }

    if !r.matches.is_empty() {
        println!("Indicator matches ({}):", r.matches.len());
        for m in &r.matches {
            let tech = if m.technique.is_empty() {
                String::new()
            } else {
                format!(" [{}]", m.technique.join(", "))
            };
            let against = m.matched_against.as_deref().unwrap_or("command_line");
            println!("  - {} (score: {:.1}) against {}{}", m.indicator_name, m.basescore, against, tech);
            if let Some(ref s) = m.matched_substring {
                if s.len() <= 80 {
                    println!("    matched: {}", s);
                } else {
                    println!("    matched: {}...", &s[..77]);
                }
            }
        }
    } else {
        println!("Indicator matches: (none)");
    }

    if !r.sigma_matches.is_empty() {
        println!("Sigma matches on decoded content ({}):", r.sigma_matches.len());
        for s in &r.sigma_matches {
            let level = s.level.as_deref().unwrap_or("-");
            println!("  - {} [{}] {}", s.rule_title, level, s.rule_id.as_deref().unwrap_or(""));
        }
    }
}
