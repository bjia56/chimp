![A group of chimps linking arms](img/chimp.png)

# Chimp

Chimp is an executable file format that allows polyglot binaries to be represented safely in a single, cross-platform file that can be run on Windows, Mac, Linux, FreeBSD, OpenBSD, NetBSD, Solaris, and more.

## Motivation + How it works

[Cosmopolitan Libc](https://github.com/jart/cosmopolitan), which uses the [Actually Portable Executable](https://justine.lol/ape.html) (APE) file format, is the foremost implementation of a polyglot compiled binary that runs natively on multiple OSes and architectures.
While the APE file format produces executables that run as PE binaries on Windows and self-extracting scripts on Unix, recent changes in OpenBSD have made it difficult to run APEs, such as [restricting NUL bytes in scripts](https://www.undeadly.org/cgi?action=article;sid=20240924105732) and [pinning syscalls](https://man.openbsd.org/pinsyscalls.2).

Chimp aims to solve this by wrapping APE programs with a meta-program that self-extracts the APE executable and optionally an appropriate APE loader, then running them.
Instead of using the PE file format, Chimp produces a polyglot executable file that executes as a batch file on Windows and a normal script on Unix, with embedded loader programs and the APE file itself.
These embedded files are stored in base64 and decoded once the first time the program runs on a given computer.
On platforms natively supported by Cosmopolitan and APE, the APE executable is extracted out and run directly, while on other plaforms, copies of the [Blink VM](https://github.com/jart/blink) can be embedded to interpret the x86_64 version of the Cosmopolitan program.

## Creating a Chimp executable

Chimp executables are created using `chimplink`. `chimplink.cpp` can be built with any C++ compiler, or download from [GitHub Releases](https://github.com/bjia56/chimp/releases/latest).

```
$ chimplink -h
Usage: ./chimplink <ape_executable> <output_file> <indicator> [--sha256 <hash>] <file1> <file2> ... --os <os_name> [--interp] <file1> <file2> [--native <file1> [--sha256 <hash>] <file2> [--sha256 <hash>]] ...
```

Before using `chimplink`, you need an APE program, such as one produced by `cosmocc`. Though `cosmocc` automates creating the APE from the x86_64 and aarch64 polyglot halves, it is highly recommended to perform the `apelink` step separately and pass in the `-S V=<indicator>` flag, where `<indicator>` can be replaced by your choice of string, such as a git commit SHA.
This will embed an (ideally unique) identifier inside the APE for the resulting Chimp file to match against when deciding whether or not to extract the executable, when a pre-existing one from a previous run already exists on disk.
Skipping the extraction and reusing a previously extracted copy significantly speeds up program startup, especially on Windows.

If customizing the `apelink` invocation is not possible, use the `--sha256` flag to provide a checksum for the APE binary, which will be used as a fallback check before extraction. This requires the `sha256sum` and `cut` programs to be available at runtime on Unix systems; on Windows, no additional dependencies are required.

Multiple custom interpreters (program loaders) could be added to the output Chimp file, using the `--os` flag to first specify an OS kernel name, followed by a list of executables on disk. These executables should be built for different hardware architectures, targeting the specified OS. The OS name should exactly match the output of `uname -s` on the platform.

An example sequence of `apelink` and `chimplink` invocations:

```
$ apelink -S "V=12345" -o prog.exe prog.com.dbg prog.aarch64.elf
$ chimplink prog.exe prog.cmd 12345 \
    --os Linux blink-linux-riscv64 blink-linux-s390x \
    --os NetBSD blink-netbsd-aarch64 \
    --os OpenBSD blink-openbsd-x86_64 blink-openbsd-aarch64
```

You can build your own Blink, or download prebuilts from [Blinkverse](https://github.com/bjia56/blinkverse/releases/latest).

## Bundling platform-native executables for Unix

If you prefer to bundle a platform-native executable which will run on the target OS instead of the APE binary through an interpreter, use the `--native` flag before listing a interpreter. This will cause the provided executable to be extracted and run on the target platform instead of the APE. By default, for each `--os` argument block, the files are treated as interpreters; use the `--native` flag to indicate the following programs are platform-native, and the `--interp` flag to indicate the subsequent programs are interpreters. For platform-native files, providing the optional `--sha256 <hash>` arguments directly after each file can help short circuit executable extraction if the `sha256sum` and `cut` programs are available at runtime.

Note that this platform-native bundling is only available for Unix. For Windows, you can work around this by replacing the APE binary with a Windows-only PE executable and use platform-native files on all other platforms.

An example:

```
$ chimplink prog.exe prog.cmd 12345 \
    --os Linux blink-linux-riscv64 --native prog.s390x --sha256 abcdef
```

For a live example of bundling an APE, Blink interpreters, and platform-native executables, see this project's [build workflow](.github/workflows/build.yml).

## Runtime requirements

On Windows, Chimp requires `cmd.exe` and `powershell.exe`.

On Unix, Chimp requires a Bourne shell and the following programs or builtins: `uname`, `dd`, `chmod`, `exec`, `mkdir`, `base64`, `tail`, `expr`, `exit`. If `base64` is unavailable, a recent version of `python3` will be tried as a backup.

## Gotchas

The underlying APE executables launched by Chimp files do not preserve `argv[0]`, instead using the file path of the extracted APE's location. Chimp defines a `CHIMP_REAL_ARGV0` environment variable to store the location of the Chimp executable.

On Windows, due to limitations of process creation, the APE executable is launched as a subprocess to the Chimp process.
