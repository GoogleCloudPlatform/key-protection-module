# Key Protection Module

This repository contains the Key Protection Module.

## How to Contribute

To make a new contribution, please follow these steps:

1. Fork the repository on GitHub.
2. Clone your forked repository:
   ```shell
   git clone --recurse-submodules <your-forked-repository-url>
   ```
3. Create a new branch for your changes:
   ```shell
   cd key-protection-module
   git checkout -b your-feature-branch
   ```
4. Make your changes to the codebase.
5. Commit your changes with a descriptive commit message:
   ```shell
   git add <files to be committed>
   git commit -m "Add new feature X"
   ```
6. Push your branch to the remote repository:
   ```shell
   git push origin your-feature-branch
   ```
7. Open a Pull Request (PR) to merge your changes into the main branch.

Please ensure all source files include the appropriate copyright and license headers. See `docs/contributing.md` for more details.

## Build Steps

To build the key manager module, follow these steps:

```shell
set -exuo pipefail
# Install build dependencies for Rust
apt-get update && apt-get install -y clang build-essential curl tar

# Install CMake 3.28.3 from pre-compiled binaries for flexibility across environments
curl -sSL https://github.com/Kitware/CMake/releases/download/v3.28.3/cmake-3.28.3-linux-x86_64.tar.gz -o cmake.tar.gz
tar -zxvf cmake.tar.gz -C /opt/
export PATH="/opt/cmake-3.28.3-linux-x86_64/bin:$PATH"
rm cmake.tar.gz

# Install bindgen-cli (needed by BoringSSL's CMake build)
cargo install bindgen-cli
export PATH="$HOME/.cargo/bin:$PATH"

# Build the Rust keymanager libraries
cd keymanager
cargo build --release
```

## Source Code Headers

Every file containing source code must include copyright and license
information. This includes any JS/CSS files that you might be serving out to
browsers. (This is to help well-intentioned people avoid accidental copying that
doesn't comply with the license.)

Apache header:

    Copyright 2024 Google LLC

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        https://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
