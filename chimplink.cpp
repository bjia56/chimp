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

struct OS {
    std::string_view name;
    std::vector<std::string_view> files;

    const std::vector<ArchAliases> get_architectures() const {
        std::vector<ArchAliases> arches;
        for (const auto& file : files) {
            arches.push_back(get_elf_architectures(file));
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
       << "if exist %E% del %E%\n"
       << "where base64 >nul 2>nul\n"
       << "if %ERRORLEVEL% NEQ 1 (\n"
       << "more +" << EXE_LINES_MARKER << " \"%S\" | base64 -d > \"%E%\"\n"
       << "goto :r\n"
       << ")\n"
       << "where openssl >nul 2>nul\n"
       << "if %ERRORLEVEL% NEQ 1 (\n"
       << "more +" << EXE_LINES_MARKER << " \"%S\" | openssl base64 -d > \"%E%\"\n"
       << "goto :r\n"
       << ")\n"
       << "powershell -Command ^\n"
       << " \"$s = Get-Content -Raw -Encoding UTF8 '%S%';\" ^\n"
       << " \"$b = $s.Substring(" << EXE_START_MARKER << ");\" ^\n"
       << " \"[IO.File]::WriteAllBytes('%E%', [Convert]::FromBase64String($b))\"\n"
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

    size_t counter = 0;
    for (const auto& os : os_list) {
        for (const auto& archs : os.get_architectures()) {
            if (archs.empty()) {
                continue;
            }
            if (os.name == "Solaris" && contains(archs, "amd64")) {
                ss << "if [ \"$m\" = i86pc ] && [ \"$k\" = SunOS ] && [ $(isainfo -b) -eq 64 ] && cat /etc/os-release | grep -qi solaris ; then\n";
            } else if (os.name == "SunOS" && contains(archs, "amd64")) {
                ss << "if [ \"$m\" = i86pc ] && [ \"$k\" = " << os.name << " ] && [ $(isainfo -b) -eq 64 ] && ; then\n";
            } else {
                ss << "if";
                for (int i = 0; i < archs.size(); ++i) {
                    const auto& arch = archs[i];
                    if (i > 0) {
                        ss << " ||";
                    }
                    ss << " [ \"$m\" = " << arch << " ]";
                }
                ss << " && [ \"$k\" = " << os.name << " ]; then\n";
            }
            ss << "dd if=\"$S\" skip=" << INTERP_START_MARKER << counter << MARKER_END
               << " count=" << INTERP_SIZE_MARKER << counter << MARKER_END
               << " bs=1 2>/dev/null | b64 > \"$I\" || exit 1\n"
               << "chmod 755 \"$I\" || exit 1\n"
               << "exec \"$I\" \"$E\" \"$@\" || exit 1\n"
               << "fi\n";
            counter++;
        }
    }

    for (const auto& file : generic_files) {
        const auto& archs = get_elf_architectures(file);
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
           << "dd if=\"$S\" skip=" << INTERP_START_MARKER << counter << MARKER_END
           << " count=" << INTERP_SIZE_MARKER << counter << MARKER_END
           << " bs=1 2>/dev/null | b64 > \"$I\" || exit 1\n"
           << "chmod 755 \"$I\" || exit 1\n"
           << "exec \"$I\" \"$E\" \"$@\" || exit 1\n"
           << "fi\n";
        counter++;
    }

    return ss.str();
}

const std::string generate_sh_script(const std::string_view& indicator, const std::vector<OS>& os_list, const std::vector<std::string_view>& generic_files) {
    std::string indicator_string = "V=" + std::string(indicator);
    std::stringstream ss;
    ss << "S=\"$0\"\n"
       << "N=$(basename \"$S\")\n"
       << "D=\"$HOME/.chimp\"\n"
       << "E=\"$D/$N\"\n"
       << "I=\"$D/.interp\"\n"
       << "if [ ! -d \"$D\" ]; then\n"
       << "mkdir -p \"$D\" || exit 1\n"
       << "fi\n"
       << "b64(){\n"
       << "if type base64 >/dev/null 2>&1; then\n"
       << "base64 -d\n"
       << "exit $?\n"
       << "elif type openssl >/dev/null 2>&1; then\n"
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
       << "rm -f \"$E\"\n"
       << "ex(){\n"
       << "i=$(expr " << EXE_START_MARKER << " + 1)\n"
       << "tail -c +$i \"$S\" 2>/dev/null || tail +${i}c \"$S\" || exit 1\n"
       << "}\n"
       << "ex | b64 > \"$E\" || exit 1\n"
       << "chmod 755 \"$E\" || exit 1\n"
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
        std::cerr << "Usage: " << argv[0] << " <ape_executable> <output_file> <indicator> <file1> <file2> ... --os <os_name> <file1> <file2> ..."
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
