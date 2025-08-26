# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Chimp is a polyglot executable wrapper tool that creates cross-platform executables by wrapping Actually Portable Executable (APE) programs from Cosmopolitan Libc. It generates executables that run as batch files on Windows and shell scripts on Unix systems.

## Core Components

### chimplink.cpp
The main source file containing the chimplink executable builder. Key components:
- **Binary format detection**: Supports ELF and Mach-O architecture detection
- **Script generation**: Creates hybrid batch/shell scripts with embedded base64-encoded payloads
- **Multi-OS support**: Handles platform-specific loaders and interpreters
- **Architecture mapping**: Maps binary architectures to platform names for runtime detection

### Architecture Support
The tool supports multiple architectures across different operating systems:
- **ELF binaries**: x86, x86_64, ARM, AArch64, PowerPC variants, s390x, RISC-V, LoongArch64
- **Mach-O binaries**: PowerPC (Power Macintosh)
- **Runtime detection**: Uses `uname -m` and `uname -s` for platform identification

## Building

### Compilation
```bash
# Build chimplink with any C++ compiler
g++ -o chimplink chimplink.cpp
# or
clang++ -o chimplink chimplink.cpp
```

### Dependencies
- C++11 or later
- Standard library support for: `<fstream>`, `<iostream>`, `<regex>`, `<sstream>`, `<unordered_map>`, `<vector>`
- POSIX headers: `<netinet/in.h>`

## Usage

### Creating Chimp Executables
```bash
# Basic usage
./chimplink <ape_executable> <output_file> <indicator>

# With OS-specific loaders
./chimplink prog.exe prog.cmd 12345 \
    --os Linux blink-linux-riscv64 blink-linux-s390x \
    --os NetBSD blink-netbsd-aarch64 \
    --os OpenBSD blink-openbsd-x86_64 blink-openbsd-aarch64
```

### Prerequisites
1. APE executable (created with cosmocc and apelink)
2. Unique indicator string (embedded with `apelink -S V=<indicator>`)
3. Optional: Platform-specific Blink VM loaders

## Implementation Details

### Script Structure
Generated executables contain:
1. **Windows batch header**: Handles Windows execution path
2. **Unix shell script**: Handles Unix execution path
3. **Embedded payloads**: Base64-encoded APE executable and interpreters
4. **Runtime caching**: Extracts and caches binaries in `~/.chimp/` (Unix) or `%USERPROFILE%\.chimp\` (Windows)

### Key Constants
- `POSITION_OF_INDICATOR = 532`: Location of version indicator in APE files
- Various markers for script generation: `C0FFEExC0DE`, `BEEFxBEEF`, etc.

### Runtime Requirements
- **Windows**: `cmd.exe`, `powershell.exe`
- **Unix**: Bourne shell, `uname`, `dd`, `chmod`, `exec`, `mkdir`, `base64`/`python3`, `tail`, `expr`