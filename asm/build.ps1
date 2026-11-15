# sRAT asm agent: nasm + mingw link (no CRT)
# usage: powershell -File build.ps1
$ErrorActionPreference = "Stop"
nasm -f win64 agent.asm -o asm-agent.obj
if ($LASTEXITCODE) { exit $LASTEXITCODE }
x86_64-w64-mingw32-g++ -nostdlib -nostartfiles -o asm-agent.exe asm-agent.obj `
  -lkernel32 -lws2_32 -lsecur32 -lcrypt32 -ladvapi32 -luser32 -lgdi32 `
  "-Wl,-e,start" "-Wl,--subsystem,console"
exit $LASTEXITCODE
