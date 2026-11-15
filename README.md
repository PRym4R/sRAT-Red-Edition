# sRAT Red Edition

Self-contained copy: Windows panel (C++) + agent written in pure NASM x64.
No C++ agent here — `asm/agent.asm` is the only agent.

```
panel/panel.cpp        panel UI, TLS server, auth
common/proto.h         wire protocol, PSK, keepalive
common/tls.h           SChannel client/server, pin check
common/util.h          file helpers
asm/agent.asm          the agent (nasm -f win64)
cert.pfx               panel certificate (agent pin matches it)
panel.exe              prebuilt panel
asm/asm-agent.exe      prebuilt agent
```

Build everything:

```
powershell -File build.ps1
```

Run:

1. `panel.exe` -> Start listening (port 8443)
2. `asm\asm-agent.exe` (or `asm\asm-agent.exe 10.0.0.5:8443`)

The agent dials the baked-in server (`sa_in` in `asm/agent.asm`, 127.0.0.1:8443),
pins the SHA-256 of `cert.pfx`, answers the PSK challenge, then serves hello,
sysinfo, shell, file list/get/put and screenshots.

Note: `cert.pfx`, `panel.exe` and `asm/asm-agent.exe` are build/secret
artifacts and are not in git. Generate your own certificate and update the
pin in `asm/agent.asm` (`pin:`), or drop the existing `cert.pfx` next to
`panel.exe`.
