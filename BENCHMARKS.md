# Benchmarks

`cargo bench -p llm-inspect --bench inspect` (Criterion). Numbers below were taken on
2026-11-09 with the bundled default rules (23 rules), Rust 1.99.1, Windows 11,
**AMD Ryzen 7 5700G**, `--warm-up-time 1 --measurement-time 2`. They are indicative;
run the benchmark on your own machine for decisions.

Inputs: `clean` is prose (English and Japanese sentences) with nothing to detect;
`mixed` is the same prose plus an email, a phone number, a card number, an AWS
key and two injection phrases; `evasive` is prose plus full-width and zero-width
obfuscated injection phrases.

| Benchmark | Time (median) | Throughput |
|---|---:|---:|
| `build/default_rules` (compile 23 rules) | 9.9 ms | — |
| `scan/clean/256` | 7.0 µs | 54 MiB/s |
| `scan/mixed/256` | 11.0 µs | 20 MiB/s |
| `scan/evasive/256` | 5.6 µs | 42 MiB/s |
| `scan/clean/4096` | 74.7 µs | 54 MiB/s |
| `scan/mixed/4096` | 89.9 µs | 43 MiB/s |
| `scan/evasive/4096` | 74.3 µs | 53 MiB/s |
| `scan/clean/65536` | 1.19 ms | 53 MiB/s |
| `scan/mixed/65536` | 1.36 ms | 46 MiB/s |
| `scan/evasive/65536` | 1.15 ms | 54 MiB/s |
| `redact/mixed/4096` | 95.5 µs | — |
| `validate/valid_plan_20_steps` (schema + allow-list + HTML) | 27.6 µs | — |
| `validate/invalid_plan` | 3.0 µs | — |

Scanning is linear in input size (the regex crate guarantees linear-time
matching), so a typical prompt of a few kilobytes is inspected in well under a
millisecond. Building an `Inspector` costs about 10 ms and should be done once.

## What the first run taught

The first version of the default rules used Unicode word boundaries (`\b`) and
scanned at about **2.3 MiB/s** (160 µs for 256 bytes). The `evasive` input was
25x faster than the `clean` one, which made no sense until the cause became
clear: once the text contains any non-ASCII character (Japanese prose, in this
case), the regex crate cannot use its lazy DFA for a pattern with a Unicode `\b`
and falls back to the slower PikeVM. The evasive input happened to normalize to
pure ASCII and therefore stayed on the fast path.

Switching every `\b` in the default rules to the ASCII word boundary `(?-u:\b)`
made scanning about **22x faster** with identical test results, because every
default rule only ever needs to anchor on ASCII tokens (keys, emails, English
words). Custom rules that must anchor on non-ASCII words can still use `\b`; the
cost applies only to those rules.
