# Declared-egress parser fuzz targets

`fuzz_connect_head` and `fuzz_client_hello` read one raw input from standard
input, call the production parsers, and check successful parse invariants.
The checked-in corpora under `corpus/` contain canonical, malformed,
truncated, split-record, and boundary-sized inputs. Reproduce them with
`python3 tools/fuzz/generate_egress_seeds.py`.

Build with `cargo build -p proofbound-runtime-linux --examples`. An external
stdin fuzzer can run either target, for example:

```sh
afl-fuzz -n -i tools/fuzz/corpus/connect -o /tmp/pbr-connect-fuzz -- \
  target/debug/examples/fuzz_connect_head
afl-fuzz -n -i tools/fuzz/corpus/client-hello -o /tmp/pbr-hello-fuzz -- \
  target/debug/examples/fuzz_client_hello
```

The native release claim still requires the separate section 9.3 corpus on
both architectures; these parser targets do not establish a Linux boundary.
