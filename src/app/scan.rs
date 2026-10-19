use std::fs;
use std::path::{Path, PathBuf};

use crate::{IoContext, Result};

const SKIPPED_DIRECTORIES: [&str; 5] = [".git", "target", "node_modules", ".shieldenv", ".venv"];
const TEMPLATE_SUFFIXES: [&str; 4] = [".example", ".sample", ".template", ".dist"];
const MAX_FILE_LEN: u64 = 1 << 20;
const MAX_FILES: usize = 200_000;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    pub path: PathBuf,
    pub line: Option<usize>,
    pub kind: &'static str,
}

struct Signature {
    kind: &'static str,
    prefixes: &'static [&'static str],
    minimum_tail: usize,
    tail: fn(u8) -> bool,
}

const SIGNATURES: [Signature; 7] = [
    Signature {
        kind: "AWS access key id",
        prefixes: &["AKIA", "ASIA"],
        minimum_tail: 16,
        tail: is_upper_alphanumeric,
    },
    Signature {
        kind: "GitHub token",
        prefixes: &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        minimum_tail: 36,
        tail: is_alphanumeric,
    },
    Signature {
        kind: "GitHub fine-grained token",
        prefixes: &["github_pat_"],
        minimum_tail: 22,
        tail: is_word,
    },
    Signature {
        kind: "Stripe live key",
        prefixes: &["sk_live_", "rk_live_"],
        minimum_tail: 24,
        tail: is_alphanumeric,
    },
    Signature {
        kind: "Slack token",
        prefixes: &["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"],
        minimum_tail: 10,
        tail: is_dashed,
    },
    Signature {
        kind: "Google API key",
        prefixes: &["AIza"],
        minimum_tail: 35,
        tail: is_dashed_word,
    },
    Signature {
        kind: "Anthropic or OpenAI key",
        prefixes: &["sk-ant-", "sk-proj-"],
        minimum_tail: 32,
        tail: is_dashed_word,
    },
];

pub fn scan(root: &Path) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    let mut visited = 0_usize;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).at(&directory)? {
            let entry = entry.at(&directory)?;
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if kind.is_dir() {
                if !SKIPPED_DIRECTORIES.contains(&name.as_ref()) {
                    pending.push(entry.path());
                }
            } else if kind.is_file() {
                visited += 1;
                if visited > MAX_FILES {
                    return Ok(sorted(findings));
                }
                inspect(&entry.path(), &name, &mut findings);
            }
        }
    }
    Ok(sorted(findings))
}

#[must_use]
pub fn detect(line: &str) -> Option<&'static str> {
    if line.contains("-----BEGIN ") && line.contains("PRIVATE KEY-----") {
        return Some("private key");
    }
    SIGNATURES
        .iter()
        .find(|signature| matches_signature(line, signature))
        .map(|signature| signature.kind)
}

fn inspect(path: &Path, name: &str, findings: &mut Vec<Finding>) {
    if is_environment_file(name) {
        findings.push(Finding {
            path: path.to_path_buf(),
            line: None,
            kind: "environment file",
        });
        return;
    }
    let readable = fs::metadata(path).is_ok_and(|metadata| metadata.len() <= MAX_FILE_LEN);
    let Some(text) = readable.then(|| fs::read_to_string(path).ok()).flatten() else {
        return;
    };
    for (index, line) in text.lines().enumerate() {
        if let Some(kind) = detect(line) {
            findings.push(Finding {
                path: path.to_path_buf(),
                line: Some(index + 1),
                kind,
            });
        }
    }
}

fn is_environment_file(name: &str) -> bool {
    let environment = name == ".env" || name.starts_with(".env.");
    environment
        && !TEMPLATE_SUFFIXES
            .iter()
            .any(|suffix| name.ends_with(suffix))
}

fn matches_signature(line: &str, signature: &Signature) -> bool {
    signature.prefixes.iter().any(|prefix| {
        line.match_indices(prefix).any(|(start, _)| {
            let tail = line.as_bytes().get(start + prefix.len()..).unwrap_or(&[]);
            tail.iter()
                .take_while(|&&byte| (signature.tail)(byte))
                .count()
                >= signature.minimum_tail
        })
    })
}

fn sorted(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort();
    findings
}

fn is_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

fn is_upper_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_uppercase() || byte.is_ascii_digit()
}

fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn is_dashed(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-'
}

fn is_dashed_word(byte: u8) -> bool {
    is_word(byte) || byte == b'-'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(prefix: &str, tail_len: usize) -> String {
        format!(
            "{prefix}{}",
            "a1B2".repeat(tail_len).get(..tail_len).unwrap()
        )
    }

    #[test]
    fn detects_known_token_shapes() {
        let upper_tail = "A1B2".repeat(4);
        let cases = [
            (format!("key = AKIA{upper_tail}"), "AWS access key id"),
            (format!("t: {}", token("ghp_", 36)), "GitHub token"),
            (token("github_pat_", 30), "GitHub fine-grained token"),
            (format!("\"{}\"", token("sk_live_", 30)), "Stripe live key"),
            (token("xoxb-", 20), "Slack token"),
            (token("AIza", 39), "Google API key"),
            (token("sk-ant-", 40), "Anthropic or OpenAI key"),
            (
                "-----BEGIN OPENSSH PRIVATE KEY-----".to_owned(),
                "private key",
            ),
        ];
        for (line, expected) in cases {
            assert_eq!(detect(&line), Some(expected), "{line}");
        }
    }

    #[test]
    fn ignores_look_alikes() {
        for line in [
            "",
            "AKIA",
            "AKIAshort",
            "ghp_tooshort",
            "sk_live_",
            "let message = \"-----BEGIN CERTIFICATE-----\";",
            "ordinary prose about tokens and keys",
        ] {
            assert_eq!(detect(line), None, "{line}");
        }
    }

    #[test]
    fn finds_environment_files_and_embedded_tokens() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("src");
        fs::create_dir_all(&nested).unwrap();
        fs::create_dir_all(root.path().join("node_modules")).unwrap();
        fs::write(root.path().join(".env"), "A=1").unwrap();
        fs::write(root.path().join(".env.production"), "A=1").unwrap();
        fs::write(root.path().join(".env.example"), "A=").unwrap();
        fs::write(
            nested.join("config.js"),
            format!("const a = 1;\nconst k = '{}';\n", token("ghp_", 36)),
        )
        .unwrap();
        fs::write(root.path().join("node_modules/.env"), "A=1").unwrap();
        fs::write(root.path().join("clean.txt"), "nothing here").unwrap();
        fs::write(root.path().join("binary.bin"), [0xFF, 0xFE, 0x00]).unwrap();
        let findings = scan(root.path()).unwrap();
        let summary: Vec<_> = findings
            .iter()
            .map(|finding| {
                (
                    finding.path.strip_prefix(root.path()).unwrap().to_owned(),
                    finding.line,
                    finding.kind,
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                (PathBuf::from(".env"), None, "environment file"),
                (PathBuf::from(".env.production"), None, "environment file"),
                (PathBuf::from("src/config.js"), Some(2), "GitHub token"),
            ]
        );
    }
}
