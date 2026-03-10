# Environment Setup

## Windows

Use the bootstrap script:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup_windows.ps1
```

What it does:

1. installs CMake via `winget`
2. installs WinLibs GCC toolchain via `winget`
3. configures the project with MinGW Makefiles
4. builds and runs tests

## Linux

Use the bootstrap script:

```bash
chmod +x scripts/setup_linux.sh
./scripts/setup_linux.sh
```

What it does:

1. installs compiler + CMake + build tools (`apt`/`dnf`/`yum`)
2. configures the project
3. builds and runs tests

## Manual Requirements

- C++17-compatible compiler (`g++` or `clang++`)
- CMake 3.16+
- Make/Ninja build tool
