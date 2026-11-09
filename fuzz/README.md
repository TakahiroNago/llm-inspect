# Fuzzing

Three [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets, run weekly and on
pull requests that touch the core crate (`.github/workflows/fuzz.yml`):

| Target | Input | Checks |
|---|---|---|
| `scan` | arbitrary UTF-8 text | no panic; every finding lies on char boundaries of the input and is sorted; `redact` reports the same findings as `scan`; the report serializes |
| `rules` | arbitrary TOML | invalid rule files are rejected with an error, valid ones produce an inspector that scans a fixed sample without panicking; oversized patterns hit the regex size limit instead of exhausting memory |
| `validate` | arbitrary text as model output | no panic; `is_valid()` agrees with the violation list; non-JSON input always yields a `NotJson` violation |

`corpus/<target>/seed_*` are hand-written seeds and are committed; the rest of the corpus
that libFuzzer evolves is ignored by git.

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run scan -- -max_total_time=60 -max_len=4096
```

## Windows notes

- cargo-fuzz instruments with AddressSanitizer, whose runtime
  (`clang_rt.asan_dynamic-x86_64.dll`) ships with MSVC. If the fuzzer exits with
  `STATUS_DLL_NOT_FOUND`, add the MSVC `bin\Hostx64\x64` directory to `PATH`
  (e.g. `...\VC\Tools\MSVC\<version>\bin\Hostx64\x64`).
- `-s none` does not link on MSVC (`__start___sancov_cntrs` is missing); keep the default sanitizer.
- If `fuzz/target` cannot be created, pass `--target-dir <somewhere writable>`.
