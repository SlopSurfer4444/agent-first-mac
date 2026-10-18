# Native identity probes

The frozen binaries were built on macOS27 with Apple clang21.0.0 (clang-2100.3.34.2), arm64-apple-darwin27.0.0, CLT SDK27.0. From this directory's native-identity subdirectory, the corresponding source build is:

```
/usr/bin/clang -Wall -Wextra -Werror -O2 probe.c -o OUTPUT/probe
/usr/bin/clang -Wall -Wextra -Werror -O2 prefix_probe.c -o OUTPUT/prefix_probe
```

Use an existing private OUTPUT directory. prefix_probe.c includes the adjacent probe.c. The original commands used those same flags and relative Wave7 paths; their exact history and source/output hashes are retained in the private delivery evidence BUILD.md and build-receipt.json. Compiler/SDK text was queried at receipt creation, not saved at original compile time. No byte-identical rebuild on a different toolchain is claimed. Installation consumes the reviewed frozen output hashes; a rebuild requires a coherently pinned reviewed successor.
