#!/usr/bin/env bash
set -euo pipefail

if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y build-essential cmake ninja-build
elif command -v dnf >/dev/null 2>&1; then
  sudo dnf install -y gcc-c++ cmake ninja-build make
elif command -v yum >/dev/null 2>&1; then
  sudo yum install -y gcc-c++ cmake ninja-build make
else
  echo "Unsupported package manager. Install a C++17 compiler, CMake, and a build tool manually."
  exit 1
fi

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure

echo "Setup complete."
