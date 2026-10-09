# OSSEC fuzz harnesses (OSS-Fuzz)

First slice for [issue #1789](https://github.com/ossec/ossec-hids/issues/1789):
`fuzz_os_xml` exercises `OS_ReadXML` and node walks in `os_xml`.

ClusterFuzz findings from OSS-Fuzz (security and non-exploitable memory
bugs) are treated as bugs to fix in this repository.

## Local build (clang + libFuzzer + ASan)

```bash
cd src
make clean-internals
make fuzz_os_xml CC=clang USE_HARDENING=no \
  CFLAGS='-O1 -g -fPIC -fsanitize=fuzzer,address -fno-omit-frame-pointer'
```

OSS-Fuzz sets `LIB_FUZZING_ENGINE` and sanitizer flags in the
environment; the same target links against that engine when present.

## Run over the seed corpus

```bash
./fuzz_os_xml -runs=5000 tests/fuzz/corpus_os_xml
```

Broken or invalid XML must return from the harness without crashing
(failed parse is a normal input).
