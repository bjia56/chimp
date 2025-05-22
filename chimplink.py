import base64
import os
import struct
import sys


EXE_START_MARKER = "C0FFEExC0DE"
EXE_SIZE_MARKER = "0x0x0x0x0x"
INTERP_START_MARKER = "BEEFxBEEF"
INTERP_SIZE_MARKER = "L337xL337"
EOF_MARKER = "EOM"

# We assume the APE executable provided as input has a special
# marker at the beginning to identify its uniqueness. This marker
# should always start with "V=".
# This is added with the -S flag of apelink.
POSITION_OF_INDICATOR = 532


def generate_batch_script(indicator: str) -> str:
    """
    Generates a batch script to extract the executable on Windows.
    """
    indicator = "V=" + indicator
    return f""": <<{EOF_MARKER}
@echo off
set S=%~f0
set N=%~n0
set D=%USERPROFILE%\\.chimp
set E=%D%\\%N%.exe
if not exist "%D%" mkdir "%D%"
powershell -Command ^
 "$file = '%E%';" ^
 "if (Test-Path $file) {{" ^
 "$fs = [System.IO.File]::Open($file, 'Open', 'Read', 'Read');" ^
 "try {{" ^
 "$fs.Seek({POSITION_OF_INDICATOR}, 'Begin') | Out-Null;" ^
 "$bytes = New-Object byte[] {len(indicator)};" ^
 "$count = $fs.Read($bytes, 0, {len(indicator)});" ^
 "$str = [System.Text.Encoding]::ASCII.GetString($bytes);" ^
 "if ($count -eq {len(indicator)} -and $str -eq '{indicator}') {{ exit 0 }}" ^
 "else {{ exit 1 }}" ^
 "}} finally {{ $fs.Close() }}" ^
 "}} else {{ exit 1 }}"
if %ERRORLEVEL% NEQ 0 (
if exist %E% del %E%
powershell -Command ^
 "$s = Get-Content -Raw -Encoding UTF8 '%S%';" ^
 "$b = $s.Substring({EXE_START_MARKER});" ^
 "[IO.File]::WriteAllBytes('%E%', [Convert]::FromBase64String($b))"
)
"%E%" %*
exit /b %ERRORLEVEL%
{EOF_MARKER}"""


class OS:
    """
    Represents an operating system with its name and associated files.
    """
    def __init__(self, name: str, files: list[str] = None):
        self.name = name
        self.files = files if files is not None else []

    def architectures(self) -> list[list[str]]:
        """
        Returns a list of architectures for the files associated with this OS.
        """
        archs = list()
        for filename in self.files:
            try:
                archs.append(get_elf_architecture(filename))
            except ValueError as e:
                print(f"Error reading {filename}: {e}")
            except Exception as e:
                print(f"Unexpected error reading {filename}: {e}")
        return archs


def generate_os_conditionals(groups: list[OS]) -> str:
    """
    Generates OS-specific conditionals for the batch script.
    """
    result = f"""m=$(uname -m 2>/dev/null) || m=x86_64
k=$(uname -s 2>/dev/null) || k=unknown
"""
    counter = 0
    for os in groups:
        os_name = os.name
        arches = os.architectures()
        if not arches:
            continue

        # Generate conditions for each architecture
        for arch in arches:
            result += f"if" + "||".join([f' [ "$m" = {a} ] ' for a in arch]) + f""" && [ "$k" = {os_name} ]; then
dd if="$S" skip={INTERP_START_MARKER + str(counter)} count={INTERP_SIZE_MARKER + str(counter)} bs=1 2>/dev/null | b64 > "$I" || exit 1
chmod 755 "$I" || exit 1
exec "$I" "$E" "$@" || exit 1
fi
"""
            counter += 1

    return result[:-1]  # Remove the last newline



def generate_sh_script(indicator: str, groups: list[OS]) -> str:
    """
    Generates a shell script to extract the executable on Unix-like systems.
    """
    indicator = "V=" + indicator
    return f"""S="$0"
N=$(basename "$S")
D="${{TMPDIR:-${{HOME:-.}}}}/.chimp"
E="$D/$N"
I="$D/.interp"
if [ ! -d "$D" ]; then
mkdir -p "$D" || exit 1
fi
b64(){{
if type base64 >/dev/null 2>&1; then
base64 -d
else
for v in 3 3.13 3.12 3.11 3.10 3.9; do
if type python$v >/dev/null 2>&1; then
python$v -c 'import base64,sys;sys.stdout.buffer.write(base64.b64decode(sys.stdin.read()))'
exit 0
fi
done
exit 1
fi
}}
if [ ! -e "$E" ] || [ "$(dd if="$E" bs=1 skip={POSITION_OF_INDICATOR} count={len(indicator)} 2>/dev/null)" != "{indicator}" ]; then
rm -f "$E"
dd if="$S" skip={EXE_START_MARKER} count={EXE_SIZE_MARKER} bs=1 2>/dev/null | b64 > "$E" || exit 1
chmod 755 "$E"
fi
""" + generate_os_conditionals(groups) + f"""
exec "$E" "$@"
exit $?"""


def get_elf_architecture(filename) -> list[str]:
    """
    Parses an ELF file and returns a list of architecture identifiers,
    including common uname aliases (e.g., ['amd64', 'x86_64']).
    The first value is the primary identifier (usually the Debian-style arch).
    """
    # (e_machine, is_64bit, is_little_endian) -> list of aliases (primary first)
    ARCH_MAP = {
        (0x03, False, True): ['i386', 'x86', 'x86_32'],
        (0x3E, True, True): ['amd64', 'x86_64'],
        (0x28, False, True): ['armel', 'arm', 'armv7l'],
        (0x28, False, False): ['arm', 'armeb'],
        (0xB7, True, True): ['arm64', 'aarch64', 'evbarm'],
        (0x15, True, True): ['powerpc64le', 'ppc64le'],
        (0x15, True, False): ['powerpc64', 'ppc64'],
        (0x14, False, False): ['powerpc', 'ppc', 'evbppc'],
        (0x16, True, False): ['s390x'],
        (0x16, False, False): ['s390'],
        (0xF3, True, True): ['riscv64'],
        (0xF3, False, True): ['riscv32'],
        # Add more as needed
    }

    with open(filename, 'rb') as f:
        ident = f.read(16)
        if ident[:4] != b'\x7fELF':
            raise ValueError("Not an ELF file")

        ei_class = ident[4]  # 1=32bit, 2=64bit
        ei_data = ident[5]   # 1=little, 2=big

        is_64bit = (ei_class == 2)
        is_little_endian = (ei_data == 1)
        endian = '<' if is_little_endian else '>'

        # e_machine is at offset 18 (16 + 2 bytes)
        f.seek(18)
        e_machine_bytes = f.read(2)
        e_machine = struct.unpack(endian + 'H', e_machine_bytes)[0]

        aliases = ARCH_MAP.get((e_machine, is_64bit, is_little_endian))
        if aliases:
            return aliases

        # Fallback for unknown/unsupported
        return [f'unknown (e_machine={hex(e_machine)}, 64bit={is_64bit}, little_endian={is_little_endian})']


def parse_args(argv) -> tuple[str, str, str, list[OS]]:
    """
    Parses command line arguments to group files by OS.
    Each group is a tuple of (os_name, [file1, file2, ...]).
    """
    groups: list[OS] = []
    current_os = None
    current_files = []

    if len(argv) < 4:
        print(f"Usage: {sys.argv[0]} <ape_executable> <outfile> <indicator> --os <os_name> <file1> <file2> ...")
        sys.exit(1)

    ape = argv[1]
    outfile = argv[2]
    indicator = argv[3]

    it = iter(argv[4:])
    for arg in it:
        if arg == '--os':
            if current_os and current_files:
                groups.append(OS(current_os, current_files))
                current_files = []
            current_os = next(it)
        else:
            current_files.append(arg)
    if current_os and current_files:
        groups.append(OS(current_os, current_files))
    return ape, outfile, indicator, groups


def read_to_base64(filename) -> str:
    """
    Reads a file and encodes its content to base64.
    """
    with open(filename, 'rb') as f:
        content = f.read()
    return base64.b64encode(content).decode('utf-8')


if __name__ == "__main__":
    ape, out, indicator, groups = parse_args(sys.argv)
    script = generate_batch_script(indicator) + "\n" + generate_sh_script(indicator, groups) + "\n"

    data_start = len(script)
    counter = 0
    for os in groups:
        files = os.files
        for filename in files:
            os_file = read_to_base64(filename)
            os_file_len = str(len(os_file))
            os_file_len_padded = os_file_len + (len(INTERP_SIZE_MARKER + str(counter)) - len(os_file_len)) * ' '
            os_file_start = str(data_start)
            os_file_start_padded = os_file_start + (len(INTERP_START_MARKER + str(counter)) - len(os_file_start)) * ' '
            script = script.replace(INTERP_SIZE_MARKER + str(counter), os_file_len_padded)
            script = script.replace(INTERP_START_MARKER + str(counter), os_file_start_padded)
            script = script + os_file
            data_start += len(os_file)
            counter += 1

    ape_file = read_to_base64(ape)
    ape_file_len = str(len(ape_file))
    ape_file_len_padded = ape_file_len + (len(EXE_SIZE_MARKER) - len(ape_file_len)) * ' '
    ape_file_start = str(data_start)
    ape_file_start_padded = ape_file_start + (len(EXE_START_MARKER) - len(ape_file_start)) * ' '
    script = script.replace(EXE_SIZE_MARKER, ape_file_len_padded)
    script = script.replace(EXE_START_MARKER, ape_file_start_padded)
    script = script + ape_file
    with open(out, 'w') as f:
        f.write(script)