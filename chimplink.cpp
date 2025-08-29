#include <algorithm>
#include <fstream>
#include <iostream>
#include <regex>
#include <string>
#include <string_view>
#include <sstream>
#include <unordered_map>
#include <vector>

#include <netinet/in.h>

const std::string_view EXE_START_MARKER = "C0FFEExC0DE";
const std::string_view EXE_SIZE_MARKER = "0x0x0x0x0x";
const std::string_view EXE_LINES_MARKER = "2b2b";
const std::string_view INTERP_START_MARKER = "BEEFxBEEF";
const std::string_view INTERP_SIZE_MARKER = "L337xL337";
const std::string_view MARKER_END = "E";

// We assume the APE executable provided as input has a special
// marker at the beginning to identify its uniqueness. This marker
// should always start with "V=".
// This is added with the -S flag of apelink.
const size_t POSITION_OF_INDICATOR = 532;

bool contains(const std::vector<std::string_view>& vec, const std::string_view& value) {
    return std::find(vec.begin(), vec.end(), value) != vec.end();
}

struct Arch {
    size_t machine;
    bool is64bit;
    bool isLE;

    bool operator==(const Arch& other) const {
        return machine == other.machine && is64bit == other.is64bit && isLE == other.isLE;
    }
};

template<>
struct std::hash<Arch> {
    size_t operator()(const Arch& arch) const {
        std::stringstream ss;
        ss << arch.machine << arch.is64bit << arch.isLE;
        return std::hash<std::string>()(ss.str());
    }
};

typedef std::vector<std::string_view> ArchAliases;

const ArchAliases& get_elf_architectures(const std::string_view& filename) {
    static const std::unordered_map<Arch, ArchAliases> ARCH_MAP = {
        {{0x03, false, true}, {"i386", "i686"}},
        {{0x3e, true, true}, {"amd64", "x86_64"}},
        {{0x28, false, true}, {"armv7l"}},
        {{0xb7, true, true}, {"aarch64", "arm64", "evbarm"}},
        {{0x15, true, true}, {"powerpc64le", "ppc64le"}},
        {{0x15, true, false}, {"powerpc64", "ppc64"}},
        {{0x14, false, false}, {"powerpc", "ppc", "evbppc"}},
        {{0x16, false, false}, {"s390"}},
        {{0x16, true, false}, {"s390x"}},
        {{0xf3, true, true}, {"riscv64"}},
        {{0xf3, false, true}, {"riscv32"}},
        {{0x102, true, true}, {"loongarch64"}},
    };

    std::ifstream file(filename.data(), std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + std::string(filename));
    }

    // Verify ELF magic number
    char magic[4];
    file.read(magic, 4);
    if (file.gcount() < 4 || magic[0] != 0x7f || magic[1] != 'E' || magic[2] != 'L' || magic[3] != 'F') {
        throw std::runtime_error("Not a valid ELF file: " + std::string(filename));
    }

    // Read the class (32-bit or 64-bit)
    char elf_class;
    file.seekg(4, std::ios::beg);
    file.read(&elf_class, 1);
    if (!file) {
        throw std::runtime_error("Failed to read ELF class from file: " + std::string(filename));
    }
    bool is64bit = (elf_class == 2); // 2 means ELF64, 1 means ELF32

    // Read the data encoding (little-endian or big-endian)
    char data_encoding;
    file.read(&data_encoding, 1);
    if (!file) {
        throw std::runtime_error("Failed to read data encoding from ELF file: " + std::string(filename));
    }
    bool isLE = (data_encoding == 1); // 1 means little-endian, 2 means big-endian

    // Read the machine type
    uint16_t machine;
    file.seekg(18, std::ios::beg);
    file.read(reinterpret_cast<char*>(&machine), sizeof(machine));
    if (!file) {
        throw std::runtime_error("Failed to read machine type from ELF file: " + std::string(filename));
    }
    if (!isLE) {
        machine = ntohs(machine); // Convert to host byte order if necessary
    }

    Arch arch = {machine, is64bit, isLE};
    auto it = ARCH_MAP.find(arch);
    if (it != ARCH_MAP.end()) {
        return it->second;
    } else {
        throw std::runtime_error("Unknown architecture for ELF file: " + std::string(filename));
    }
}

// (cputype, is64bit)
struct MachoArch {
    int32_t cputype;
    bool is64bit;

    bool operator==(const MachoArch& other) const {
        return cputype == other.cputype && is64bit == other.is64bit;
    }
};

template <>
struct std::hash<MachoArch> {
    size_t operator()(const MachoArch& a) const {
        return hash<int32_t>()(a.cputype) ^ (hash<bool>()(a.is64bit) << 1);
    }
};

// XCOFF architecture structure
struct XcoffArch {
    uint16_t cputype;
    bool is64bit;

    bool operator==(const XcoffArch& other) const {
        return cputype == other.cputype && is64bit == other.is64bit;
    }
};

template <>
struct std::hash<XcoffArch> {
    size_t operator()(const XcoffArch& arch) const {
        return hash<uint16_t>()(arch.cputype) ^ (hash<bool>()(arch.is64bit) << 1);
    }
};

// Mach-O magic numbers
constexpr uint32_t MH_MAGIC      = 0xFEEDFACE;
constexpr uint32_t MH_CIGAM      = 0xCEFAEDFE;
constexpr uint32_t MH_MAGIC_64   = 0xFEEDFACF;
constexpr uint32_t MH_CIGAM_64   = 0xCFFAEDFE;
constexpr uint32_t FAT_MAGIC     = 0xCAFEBABE;
constexpr uint32_t FAT_CIGAM     = 0xBEBAFECA;

// Mach-O CPU types (subset)
constexpr int32_t CPU_TYPE_X86        = 7;
constexpr int32_t CPU_TYPE_X86_64     = (CPU_TYPE_X86 | 0x01000000);
constexpr int32_t CPU_TYPE_ARM        = 12;
constexpr int32_t CPU_TYPE_ARM64      = (CPU_TYPE_ARM | 0x01000000);
constexpr int32_t CPU_TYPE_POWERPC    = 18;
constexpr int32_t CPU_TYPE_POWERPC64  = (CPU_TYPE_POWERPC | 0x01000000);

// XCOFF magic numbers
constexpr uint16_t XCOFF_MAGIC_32    = 0x01DF;  // 32-bit XCOFF
constexpr uint16_t XCOFF_MAGIC_64    = 0x01F7;  // 64-bit XCOFF

// XCOFF CPU types (from AIX header files)
constexpr uint16_t XCOFF_CPU_POWER   = 0x0001;  // POWER architecture
constexpr uint16_t XCOFF_CPU_PPC     = 0x0002;  // PowerPC
constexpr uint16_t XCOFF_CPU_PPC64   = 0x0003;  // PowerPC 64-bit

// XCOFF file header (32-bit)
struct xcoff_filehdr {
    uint16_t f_magic;     // Magic number
    uint16_t f_nscns;     // Number of sections
    uint32_t f_timdat;    // Time & date stamp
    uint32_t f_symptr;    // File pointer to symtab
    uint32_t f_nsyms;     // Number of symtab entries
    uint16_t f_opthdr;    // sizeof(optional hdr)
    uint16_t f_flags;     // Flags
};

// XCOFF file header (64-bit)
struct xcoff_filehdr_64 {
    uint16_t f_magic;     // Magic number
    uint16_t f_nscns;     // Number of sections
    uint32_t f_timdat;    // Time & date stamp
    uint64_t f_symptr;    // File pointer to symtab
    uint32_t f_nsyms;     // Number of symtab entries
    uint16_t f_opthdr;    // sizeof(optional hdr)
    uint16_t f_flags;     // Flags
};

static const std::unordered_map<MachoArch, ArchAliases> MACHO_ARCH_MAP = {
    {{CPU_TYPE_POWERPC, false}, {"Power Macintosh"}},
};

static const std::unordered_map<XcoffArch, ArchAliases> XCOFF_ARCH_MAP = {
    {{XCOFF_CPU_POWER, false}, {"power", "powerpc", "ppc"}},
    {{XCOFF_CPU_PPC, false}, {"powerpc", "ppc", "power"}},
    {{XCOFF_CPU_PPC64, true}, {"powerpc64", "ppc64", "power64"}},
};

inline uint32_t swap32(uint32_t x) {
    return ((x>>24)&0xff) | ((x<<8)&0xff0000) | ((x>>8)&0xff00) | ((x<<24)&0xff000000);
}
inline int32_t swap32(int32_t x) {
    return static_cast<int32_t>(swap32(static_cast<uint32_t>(x)));
}

// Mach-O 32-bit header
struct mach_header {
    uint32_t magic;
    int32_t cputype;
    int32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
};

// Mach-O 64-bit header
struct mach_header_64 {
    uint32_t magic;
    int32_t cputype;
    int32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
};

// Fat header structs
struct fat_header {
    uint32_t magic;
    uint32_t nfat_arch;
};
struct fat_arch {
    int32_t cputype;
    int32_t cpusubtype;
    uint32_t offset;
    uint32_t size;
    uint32_t align;
};

const ArchAliases& get_macho_architectures(const std::string_view& filename) {
    static ArchAliases result; // For returning from function (thread-unsafe, similar to your ELF usage)

    std::ifstream file(filename.data(), std::ios::binary);
    if (!file)
        throw std::runtime_error("Failed to open file: " + std::string(filename));

    uint32_t magic;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    if (file.gcount() != 4)
        throw std::runtime_error("File too short: " + std::string(filename));

    bool is_fat = (magic == FAT_MAGIC || magic == FAT_CIGAM);
    bool swap = (magic == FAT_CIGAM || magic == MH_CIGAM || magic == MH_CIGAM_64);

    if (is_fat) {
        // Universal binary
        fat_header fh;
        file.seekg(0, std::ios::beg);
        file.read(reinterpret_cast<char*>(&fh), sizeof(fh));
        if (swap) {
            fh.nfat_arch = swap32(fh.nfat_arch);
        }
        if (fh.nfat_arch == 0 || fh.nfat_arch > 16)
            throw std::runtime_error("Suspicious nfat_arch: " + std::string(filename));

        // Read all contained architectures, return the first known
        for (uint32_t i = 0; i < fh.nfat_arch; ++i) {
            fat_arch arch;
            file.read(reinterpret_cast<char*>(&arch), sizeof(arch));
            int32_t cputype = swap ? swap32(arch.cputype) : arch.cputype;
            // Seek to offset, read magic
            uint32_t offset = swap ? swap32(arch.offset) : arch.offset;
            std::streampos saved = file.tellg();
            file.seekg(offset, std::ios::beg);
            uint32_t inner_magic = 0;
            file.read(reinterpret_cast<char*>(&inner_magic), 4);
            bool is64 = (inner_magic == MH_MAGIC_64 || inner_magic == MH_CIGAM_64);

            MachoArch mkey = {cputype, is64};
            auto it = MACHO_ARCH_MAP.find(mkey);
            if (it != MACHO_ARCH_MAP.end()) {
                result = it->second;
                return result;
            }
            file.seekg(saved);
        }
        throw std::runtime_error("Unknown architecture in FAT Mach-O: " + std::string(filename));
    }

    // Thin Mach-O (32 or 64)
    file.seekg(0, std::ios::beg);
    mach_header_64 hdr64;
    file.read(reinterpret_cast<char*>(&hdr64), sizeof(hdr64));
    if (file.gcount() < 8) // At least magic + cputype
        throw std::runtime_error("File too short for Mach-O header: " + std::string(filename));

    uint32_t m = hdr64.magic;
    bool is64 = (m == MH_MAGIC_64 || m == MH_CIGAM_64);
    int32_t cputype = swap ? swap32(hdr64.cputype) : hdr64.cputype;

    MachoArch mkey = {cputype, is64};
    auto it = MACHO_ARCH_MAP.find(mkey);
    if (it != MACHO_ARCH_MAP.end()) {
        result = it->second;
        return result;
    }
    throw std::runtime_error("Unknown architecture for Mach-O file: " + std::string(filename));
}

const ArchAliases& get_xcoff_architectures(const std::string_view& filename) {
    static ArchAliases result; // For returning from function (thread-unsafe, similar to ELF/Mach-O usage)

    std::ifstream file(filename.data(), std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + std::string(filename));
    }

    // Read XCOFF header (both 32-bit and 64-bit share the same first few fields)
    xcoff_filehdr hdr;
    file.read(reinterpret_cast<char*>(&hdr), sizeof(xcoff_filehdr));
    if (file.gcount() < sizeof(xcoff_filehdr)) {
        throw std::runtime_error("File too short for XCOFF header: " + std::string(filename));
    }

    // Check for XCOFF magic numbers (AIX uses big-endian format)
    uint16_t magic = ntohs(hdr.f_magic);
    bool is64bit = false;

    if (magic == XCOFF_MAGIC_32) {
        is64bit = false;
    } else if (magic == XCOFF_MAGIC_64) {
        is64bit = true;
    } else {
        throw std::runtime_error("Not a valid XCOFF file: " + std::string(filename));
    }

    // For 64-bit XCOFF, we need to read additional fields, but CPU type is still in the same place
    // The CPU type information in XCOFF is typically derived from the target machine
    // For simplicity, we'll assume PowerPC family based on magic number
    uint16_t cputype;
    if (is64bit) {
        cputype = XCOFF_CPU_PPC64;
    } else {
        // For 32-bit XCOFF, we assume PowerPC (could also be POWER, but PowerPC is more common)
        cputype = XCOFF_CPU_PPC;
    }

    XcoffArch xcoff_arch = {cputype, is64bit};
    auto it = XCOFF_ARCH_MAP.find(xcoff_arch);
    if (it != XCOFF_ARCH_MAP.end()) {
        result = it->second;
        return result;
    } else {
        throw std::runtime_error("Unknown architecture for XCOFF file: " + std::string(filename));
    }
}

const ArchAliases& get_architectures(const std::string_view& filename) {
    try {
        return get_elf_architectures(filename);
    } catch (const std::runtime_error&) {
        // If ELF parsing fails, try Mach-O
        try {
            return get_macho_architectures(filename);
        } catch (const std::runtime_error&) {
            // If Mach-O parsing fails, try XCOFF
            try {
                return get_xcoff_architectures(filename);
            } catch (const std::runtime_error&) {
                throw std::runtime_error("Failed to determine architecture for non-ELF, non-Mach-O, and non-XCOFF file: " + std::string(filename));
            }
        }
    }
}

struct OS {
    std::string_view name;
    std::vector<std::string_view> files;

    const std::vector<ArchAliases> get_architectures() const {
        std::vector<ArchAliases> arches;
        for (const auto& file : files) {
            arches.push_back(::get_architectures(file));
        }
        return arches;
    }
};

const std::string generate_batch_script(const std::string_view& indicator) {
    std::string indicator_string = "V=" + std::string(indicator);
    std::stringstream ss;
    ss << ": <<EOM\n"
       << "@echo off\n"
       << "set S=%~f0\n"
       << "set N=%~n0\n"
       << "set D=%USERPROFILE%\\.chimp\n"
       << "set E=%D%\\%N%.exe\n"
       << "set \"CHIMP_REAL_ARGV0=%0\"\n"
       << "if not exist \"%D%\" mkdir \"%D%\"\n"
       << "powershell -Command ^\n"
       << " \"$e = '%E%';\" ^\n"
       << " \"if (Test-Path $e) {\" ^\n"
       << " \"$f = [System.IO.File]::Open($e, 'Open', 'Read', 'Read');\" ^\n"
       << " \"try {\" ^\n"
       << " \"$f.Seek(" << POSITION_OF_INDICATOR << ", 'Begin') | Out-Null;\" ^\n"
       << " \"$b = New-Object byte[] " << indicator_string.length() << ";\" ^\n"
       << " \"$c = $f.Read($b, 0, " << indicator_string.length() << ");\" ^\n"
       << " \"$s = [System.Text.Encoding]::ASCII.GetString($b);\" ^\n"
       << " \"if ($c -eq " << indicator_string.length() << " -and $s -eq '" << indicator_string << "') { exit 0 }\" ^\n"
       << " \"else { exit 1 }\" ^\n"
       << " \"} finally { $f.Close() }\" ^\n"
       << " \"} else { exit 1 }\"\n"
       << "if %ERRORLEVEL% NEQ 0 (\n"
       << "<nul set /p=Extracting executable... 1>&2\n"
       << "if exist %E% del %E%\n"
       << "where base64 >nul 2>nul\n"
       << "if %ERRORLEVEL% NEQ 1 (\n"
       << "more +" << EXE_LINES_MARKER << " \"%S\" | base64 -d > \"%E%\"\n"
       << "echo complete. >&2\n"
       << "goto :r\n"
       << ")\n"
       << "where openssl >nul 2>nul\n"
       << "if %ERRORLEVEL% NEQ 1 (\n"
       << "more +" << EXE_LINES_MARKER << " \"%S\" | openssl base64 -d > \"%E%\"\n"
       << "echo complete. >&2\n"
       << "goto :r\n"
       << ")\n"
       << "powershell -Command ^\n"
       << " \"$s = Get-Content -Raw -Encoding UTF8 '%S%';\" ^\n"
       << " \"$b = $s.Substring(" << EXE_START_MARKER << ");\" ^\n"
       << " \"[IO.File]::WriteAllBytes('%E%', [Convert]::FromBase64String($b))\"\n"
       << "echo complete. >&2\n"
       << ")\n"
       << ":r\n"
       << "\"%E%\" %*\n"
       << "exit /b %ERRORLEVEL%\n"
       << "EOM";
    return ss.str();
}

const std::string generate_os_conditionals(const std::vector<OS>& os_list, const std::vector<std::string_view>& generic_files) {
    std::stringstream ss;
    ss << "m=$(uname -m 2>/dev/null) || m=unknown\n"
       << "k=$(uname -s 2>/dev/null) || k=unknown\n"
       << "if [ -e \"$I\" ]; then\n"
       << "exec \"$I\" \"$E\" \"$@\" || exit 1\n"
       << "fi\n";

    ss << "exb(){\n"
       << "s=$2\n" // start
       << "l=$3\n" // length
       << "b=4096\n" // block size
       << "sb=$((s/b*b))\n" // start block
       << "e=$((s+l))\n" // end
       << "eb=$(((e+b-1)/b*b))\n" // end block
       << "if [ \"$s\" -gt \"$sb\" ];then\n"
       << "h=$((b-(s-sb)))\n" // head bytes
       << "p=$l\n" // first part length
       << "if [ \"$h\" -lt \"$l\" ];then p=$h;fi\n"
       << "dd if=\"$1\" bs=1 skip=$s count=$p 2>/dev/null\n"
       << "s=$((s+p))\n"
       << "l=$((l-p))\n"
       << "fi\n"
       << "a=$((l/b*b))\n" // aligned length
       << "if [ $a -gt 0 ];then\n"
       << "dd if=\"$1\" bs=$b skip=$((s/b)) count=$((a/b)) 2>/dev/null\n"
       << "s=$((s+a))\n"
       << "l=$((l-a))\n"
       << "fi\n"
       << "if [ $l -gt 0 ];then\n"
       << "dd if=\"$1\" bs=1 skip=$s count=$l 2>/dev/null\n"
       << "fi\n"
       << "}\n";

    size_t counter = 0;
    for (const auto& os : os_list) {
        for (const auto& archs : os.get_architectures()) {
            if (archs.empty()) {
                continue;
            }
            if (os.name == "Solaris" && contains(archs, "amd64")) {
                ss << "if [ \"$m\" = i86pc ] && [ \"$k\" = SunOS ] && [ $(isainfo -b) -eq 64 ] && cat /etc/os-release | grep -qi solaris ; then\n";
            } else if (os.name == "SunOS" && contains(archs, "amd64")) {
                ss << "if [ \"$m\" = i86pc ] && [ \"$k\" = " << os.name << " ] && [ $(isainfo -b) -eq 64 ]; then\n";
            } else if (os.name == "AIX") {
                ss << "if [ \"$k\" = AIX ]; then\n";
            } else {
                ss << "if";
                for (int i = 0; i < archs.size(); ++i) {
                    const auto& arch = archs[i];
                    if (i > 0) {
                        ss << " ||";
                    }
                    if (arch.find(" ") != std::string::npos) {
                        ss << " [ \"$m\" = \"" << arch << "\" ]";
                    } else {
                        ss << " [ \"$m\" = " << arch << " ]";
                    }
                }
                ss << " && [ \"$k\" = " << os.name << " ]; then\n";
            }
            ss << "echo -n \"Extracting interpreter... \" >&2\n"
               << "exb \"$S\" " << INTERP_START_MARKER << counter << MARKER_END
               << " " << INTERP_SIZE_MARKER << counter << MARKER_END
               << " | b64 > \"$I\" || exit 1\n"
               << "chmod 755 \"$I\" || exit 1\n"
               << "echo \"complete.\" >&2\n"
               << "exec \"$I\" \"$E\" \"$@\" || exit 1\n"
               << "fi\n";
            counter++;
        }
    }

    for (const auto& file : generic_files) {
        const auto& archs = get_architectures(file);
        if (archs.empty()) {
            continue;
        }
        ss << "if";
        for (int i = 0; i < archs.size(); ++i) {
            const auto& arch = archs[i];
            if (i > 0) {
                ss << " ||";
            }
            ss << " [ \"$m\" = " << arch << " ]";
        }
        ss << " && [ \"$k\" != Darwin ]; then\n"
           << "echo -n \"Extracting interpreter... \" >&2\n"
           << "exb \"$S\" " << INTERP_START_MARKER << counter << MARKER_END
           << " " << INTERP_SIZE_MARKER << counter << MARKER_END
           << " | b64 > \"$I\" || exit 1\n"
           << "chmod 755 \"$I\" || exit 1\n"
           << "echo \"complete.\" >&2\n"
           << "exec \"$I\" \"$E\" \"$@\" || exit 1\n"
           << "fi\n";
        counter++;
    }

    return ss.str();
}

const std::string generate_sh_script(const std::string_view& indicator, const std::vector<OS>& os_list, const std::vector<std::string_view>& generic_files) {
    std::string indicator_string = "V=" + std::string(indicator);

    // Check if AIX is in the OS list
    bool has_aix = false;
    for (const auto& os : os_list) {
        if (os.name == "AIX") {
            has_aix = true;
            break;
        }
    }

    std::stringstream ss;
    ss << "S=\"$0\"\n"
       << "N=$(basename \"$S\")\n"
       << "D=\"$HOME/.chimp\"\n"
       << "E=\"$D/$N\"\n"
       << "I=\"$D/.interp\"\n"
       << "export CHIMP_REAL_ARGV0=\"$0\"\n"
       << "if [ ! -d \"$D\" ]; then\n"
       << "mkdir -p \"$D\" || exit 1\n"
       << "fi\n"
       << "b64(){\n";

    if (has_aix) {
        // For AIX, check AIX first and use Python-based extraction
        ss << "if [ \"$(uname -s 2>/dev/null)\" = AIX ]; then\n"
           << "for v in 3 3.13 3.12 3.11 3.10 3.9; do\n"
           << "if type python$v >/dev/null 2>&1; then\n"
           << "python$v -c 'import base64,sys;sys.stdout.buffer.write(base64.b64decode(sys.stdin.read()))'\n"
           << "exit $?\n"
           << "fi\n"
           << "done\n"
           << "fi\n";
    }

    ss << "if type base64 >/dev/null 2>&1; then\n"
       << "base64 -d\n"
       << "exit $?\n"
       << "elif type gbase64 >/dev/null 2>&1; then\n"
       << "gbase64 -d\n"
       << "exit $?\n"
       << "elif type openssl >/dev/null 2>&1 && ! openssl version | grep -q LibreSSL && ! openssl version | grep -q midnightbsd; then\n"
       << "openssl base64 -d\n"
       << "exit $?\n"
       << "else\n"
       << "for v in 3 3.13 3.12 3.11 3.10 3.9; do\n"
       << "if type python$v >/dev/null 2>&1; then\n"
       << "python$v -c 'import base64,sys;sys.stdout.buffer.write(base64.b64decode(sys.stdin.read()))'\n"
       << "exit $?\n"
       << "fi\n"
       << "done\n"
       << "exit 1\n"
       << "fi\n"
       << "}\n"
       << "if [ ! -e \"$E\" ] || [ \"$(dd if=\"$E\" skip=" << POSITION_OF_INDICATOR << " bs=1 count=" << indicator_string.length() << " 2>/dev/null)\" != \"" << indicator_string << "\" ]; then\n"
       << "echo -n \"Extracting executable... \" >&2\n"
       << "rm -f \"$E\"\n"
       << "ex(){\n"
       << "i=$(expr " << EXE_START_MARKER << " + 1)\n"
       << "tail -c +$i \"$S\" 2>/dev/null || tail +${i}c \"$S\" || exit 1\n"
       << "}\n"
       << "ex | b64 > \"$E\" || exit 1\n"
       << "chmod 755 \"$E\" || exit 1\n"
       << "echo \"complete.\" >&2\n"
       << "fi\n"
       << generate_os_conditionals(os_list, generic_files) << "\n"
       << "exec \"$E\" \"$@\" || exit 1\n"
       << "exit $?";
    return ss.str();
}

void encode_block(const unsigned char in[3], char out[4], int len) {
    static const char base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    out[0] = base64_chars[(in[0] & 0xfc) >> 2];
    out[1] = base64_chars[((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4)];
    out[2] = (len > 1) ? base64_chars[((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6)] : '=';
    out[3] = (len > 2) ? base64_chars[in[2] & 0x3f] : '=';
}

const std::string read_to_base64(const std::string_view& filename) {
    std::ifstream file(std::string(filename), std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + std::string(filename));
    }

    std::ostringstream oss;
    unsigned char in[3];
    char out[4];
    int len = 0;

    while (file.good()) {
        file.read(reinterpret_cast<char *>(in), 3);
        len = static_cast<int>(file.gcount());
        if (len > 0) {
            encode_block(in, out, len);
            oss.write(out, 4);
        }
    }
    return oss.str();
}

template <typename T>
const std::string pad_number(T number, size_t length) {
    std::ostringstream oss;
    oss << number;
    std::string str = oss.str();
    if (str.length() > length) {
        throw std::runtime_error("Number exceeds padding length: " + str);
    }
    if (str.length() < length) {
        str.resize(length, ' ');
    }
    return str;
}

struct Args {
    std::string_view ape_executable;
    std::string_view output_file;
    std::string_view indicator;
    std::vector<OS> os_list;
    std::vector<std::string_view> generic_files;
};

const Args parse_args(int argc, char* argv[]) {
    Args args;

    if (argc < 4) {
        std::cerr << "Usage: ";
        const char *real_arg0 = getenv("CHIMP_REAL_ARGV0");
        if (real_arg0) {
            std::cerr << real_arg0;
        } else {
            std::cerr << argv[0];
        }
        std::cerr << " <ape_executable> <output_file> <indicator> <file1> <file2> ... --os <os_name> <file1> <file2> ..."
                  << std::endl;
        exit(EXIT_FAILURE);
    }

    args.ape_executable = argv[1];
    args.output_file = argv[2];
    args.indicator = argv[3];

    for (int i = 4; i < argc; ++i) {
        if (std::string_view(argv[i]) == "--os") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --os requires at least one OS name and one file." << std::endl;
                exit(EXIT_FAILURE);
            }
            OS os;
            os.name = argv[++i];
            while (i + 1 < argc && argv[i + 1][0] != '-') {
                os.files.push_back(argv[++i]);
            }
            args.os_list.push_back(os);
        } else {
            // Treat any other argument as a generic file
            args.generic_files.push_back(argv[i]);
        }
    }

    return args;
}

int main(int argc, char* argv[]) {
    Args args = parse_args(argc, argv);
    std::string header = generate_batch_script(args.indicator) + "\n" +
                         generate_sh_script(args.indicator, args.os_list, args.generic_files) + "\n";

    std::stringstream script;
    size_t data_start = header.length();
    size_t counter = 0;
    size_t lines = std::count(header.begin(), header.end(), '\n');
    for (const auto& os : args.os_list) {
        for (const auto& file : os.files) {
            std::string counter_str = std::to_string(counter);

            std::string encoded_file = read_to_base64(file);
            std::string file_size = pad_number(encoded_file.length(), INTERP_SIZE_MARKER.length() + counter_str.length() + MARKER_END.length());
            std::string file_start = pad_number(data_start, INTERP_START_MARKER.length() + counter_str.length() + MARKER_END.length());

            header = std::regex_replace(header, std::regex(INTERP_START_MARKER.data() + counter_str + MARKER_END.data()), file_start);
            header = std::regex_replace(header, std::regex(INTERP_SIZE_MARKER.data() + counter_str + MARKER_END.data()), file_size);

            script << encoded_file << "\n";
            data_start += encoded_file.length() + 1;
            counter++;
            lines++;
        }
    }

    for (const auto& file : args.generic_files) {
        std::string counter_str = std::to_string(counter);

        std::string encoded_file = read_to_base64(file);
        std::string file_size = pad_number(encoded_file.length(), INTERP_SIZE_MARKER.length() + counter_str.length() + MARKER_END.length());
        std::string file_start = pad_number(data_start, INTERP_START_MARKER.length() + counter_str.length() + MARKER_END.length());

        header = std::regex_replace(header, std::regex(INTERP_START_MARKER.data() + counter_str + MARKER_END.data()), file_start);
        header = std::regex_replace(header, std::regex(INTERP_SIZE_MARKER.data() + counter_str + MARKER_END.data()), file_size);

        script << encoded_file << "\n";
        data_start += encoded_file.length() + 1;
        counter++;
        lines++;
    }

    std::string ape_file = read_to_base64(args.ape_executable);
    std::string ape_size = pad_number(ape_file.length(), EXE_SIZE_MARKER.length());
    std::string ape_start = pad_number(data_start, EXE_START_MARKER.length());
    std::string ape_lines = pad_number(lines, EXE_LINES_MARKER.length());
    header = std::regex_replace(header, std::regex(EXE_START_MARKER.data()), ape_start);
    header = std::regex_replace(header, std::regex(EXE_SIZE_MARKER.data()), ape_size);
    header = std::regex_replace(header, std::regex(EXE_LINES_MARKER.data()), ape_lines);
    script << ape_file;

    std::ofstream output(args.output_file.data());
    if (!output) {
        std::cerr << "Error: Cannot open output file: " << args.output_file << std::endl;
        return EXIT_FAILURE;
    }
    output << header << script.str();
    output.close();

    return EXIT_SUCCESS;
}
