# asm agent

Win64 NASM implementation of the sRAT agent (`agent/agent.cpp` in the main tree).
No CRT, no C++: raw Win32 + SChannel, pinned SHA-256, same wire protocol.

* server: `kServer` is baked in (`sa_in` in `agent.asm`, 127.0.0.1:8443)
* commands: hello, sysinfo, shell, fs list/get/put, screenshot, bye
* build: `powershell -File build.ps1` (needs nasm + x86_64-w64-mingw32-g++)

`agent.asm` is the only source; `asm-agent.obj`/`asm-agent.exe` are build output.
