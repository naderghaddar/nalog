$ErrorActionPreference = "Stop"

Write-Host "Installing required C++ tooling with winget..."
winget install --id Kitware.CMake -e --accept-package-agreements --accept-source-agreements
winget install --id BrechtSanders.WinLibs.POSIX.UCRT -e --accept-package-agreements --accept-source-agreements

$cmakeExe = "C:\Program Files\CMake\bin\cmake.exe"
if (-not (Test-Path $cmakeExe)) {
    throw "CMake executable not found at: $cmakeExe"
}

$gccExe = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" -Recurse -Filter "g++.exe" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match "WinLibs" } |
    Select-Object -First 1 -ExpandProperty FullName

if (-not $gccExe) {
    throw "Could not locate WinLibs g++.exe under winget package directory."
}

$toolchainBin = Split-Path -Parent $gccExe
$makeExe = Join-Path $toolchainBin "mingw32-make.exe"
if (-not (Test-Path $makeExe)) {
    throw "mingw32-make.exe not found next to g++.exe."
}

$env:PATH = "$toolchainBin;$env:PATH"

Write-Host "Configuring project..."
& $cmakeExe -S . -B build -G "MinGW Makefiles" `
    -DCMAKE_BUILD_TYPE=Release `
    "-DCMAKE_CXX_COMPILER=$gccExe" `
    "-DCMAKE_MAKE_PROGRAM=$makeExe"

Write-Host "Building project..."
& $cmakeExe --build build -j

Write-Host "Running tests..."
& "C:\Program Files\CMake\bin\ctest.exe" --test-dir build --output-on-failure

Write-Host "Setup complete."
