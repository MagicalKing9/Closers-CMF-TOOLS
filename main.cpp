// Closers CMF Tools - Win32 GUI / ISO C++20 / MSVC v145 / x64
// No Qt / MFC / CMake / console UI.
// GUI: Win32 + GDI+ (Windows SDK component). Compression: zlib.

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <windowsx.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <commctrl.h>
#include <gdiplus.h>
#include <strsafe.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <regex>
#include <stdexcept>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <deque>
#include <memory>
#include <functional>
#include <cctype>

#include <zlib.h>

#include "resource.h"

#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")

namespace fs = std::filesystem;
using namespace Gdiplus;

// Forward declarations
static fs::path app_root();

// ------------------------------------------------------------
// Constants / CMF core logic (based on supplied source)
// ------------------------------------------------------------
constexpr size_t HEADER_SIZE = 104;
constexpr size_t ENTRY_SIZE = 528;
constexpr size_t TABLE_OFFSET = 0x68;

const std::map<int, uint16_t> VERSION_MARK = {
    {1, 0x0020}, {2, 0x0032}, {3, 0x0033}, {4, 0x0034}, {5, 0x0035},
    {6, 0x0036}, {7, 0x0037}, {8, 0x0038}, {9, 0x0039}, {10, 0x0031}
};

const uint32_t OLD_KEYS[3] = { 0xAC9372DE, 0x8469AF01, 0xDC39628F };
const uint32_t NEW_KEYS[3] = { 0x5FBC3A19, 0x2D8E94B6, 0xE1726C43 };
const uint32_t FILE_COUNT_KEY = OLD_KEYS[0];

static std::wstring widen_utf8(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), (int)s.size(), nullptr, 0);
    if (n <= 0) {
        n = MultiByteToWideChar(CP_ACP, 0, s.data(), (int)s.size(), nullptr, 0);
        if (n <= 0) return {};
        std::wstring out(n, L'\0');
        MultiByteToWideChar(CP_ACP, 0, s.data(), (int)s.size(), out.data(), n);
        return out;
    }
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), (int)s.size(), out.data(), n);
    return out;
}

static std::string narrow_utf8(const std::wstring& s) {
    if (s.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), (int)s.size(), out.data(), n, nullptr, nullptr);
    return out;
}

static std::wstring path_display(const fs::path& p) {
    return p.wstring();
}

static uint32_t read_u32_le(const uint8_t* p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}

static void write_u32_le(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v & 0xFF);
    p[1] = uint8_t((v >> 8) & 0xFF);
    p[2] = uint8_t((v >> 16) & 0xFF);
    p[3] = uint8_t((v >> 24) & 0xFF);
}

static std::string utf16le_to_utf8(const uint8_t* data, size_t len) {
    std::wstring ws;
    ws.reserve(len / 2);
    for (size_t i = 0; i + 1 < len; i += 2) {
        wchar_t ch = wchar_t(data[i] | (uint16_t(data[i + 1]) << 8));
        if (ch == L'\0') break;
        ws.push_back(ch);
    }
    return narrow_utf8(ws);
}

static std::vector<uint8_t> utf8_to_utf16le(const std::string& s) {
    const std::wstring ws = widen_utf8(s);
    std::vector<uint8_t> out;
    out.resize(ws.size() * 2);
    for (size_t i = 0; i < ws.size(); ++i) {
        out[i * 2] = uint8_t(ws[i] & 0xFF);
        out[i * 2 + 1] = uint8_t((ws[i] >> 8) & 0xFF);
    }
    return out;
}

static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return char(std::tolower(c)); });
    return s;
}

static std::string normalize_path_utf8(std::string path) {
    std::replace(path.begin(), path.end(), '\\', '/');
    return path;
}

static uint32_t _swap(uint32_t x) {
    return ((x << 24) | (x >> 24) | (x & 0x00FFFF00));
}

static void decrypt_table_memoryfile2_inplace(std::vector<uint8_t>& data, uint32_t key1, uint32_t key2, uint32_t key3) {
    while (data.size() % 4 != 0) data.push_back(0);
    const size_t n = data.size() / 4;
    for (size_t i = 0; i + 2 < n; i += 3) {
        uint8_t* p = data.data() + i * 4;
        uint32_t a = read_u32_le(p);
        uint32_t b = read_u32_le(p + 4);
        uint32_t c = read_u32_le(p + 8);
        write_u32_le(p, _swap(a) ^ key1);
        write_u32_le(p + 4, _swap(b) ^ key2);
        write_u32_le(p + 8, _swap(c) ^ key3);
    }
    const size_t base = (n / 3) * 3;
    for (size_t i = base; i < n; ++i) {
        uint8_t* p = data.data() + i * 4;
        write_u32_le(p, _swap(read_u32_le(p)) ^ key1);
    }
}

static void encrypt_table_memoryfile2_inplace(std::vector<uint8_t>& data, uint32_t key1, uint32_t key2, uint32_t key3) {
    while (data.size() % 4 != 0) data.push_back(0);
    const size_t n = data.size() / 4;
    for (size_t i = 0; i + 2 < n; i += 3) {
        uint8_t* p = data.data() + i * 4;
        write_u32_le(p, _swap(read_u32_le(p) ^ key1));
        write_u32_le(p + 4, _swap(read_u32_le(p + 4) ^ key2));
        write_u32_le(p + 8, _swap(read_u32_le(p + 8) ^ key3));
    }
    const size_t base = (n / 3) * 3;
    for (size_t i = base; i < n; ++i) {
        uint8_t* p = data.data() + i * 4;
        write_u32_le(p, _swap(read_u32_le(p) ^ key1));
    }
}

static void decrypt_cmf_table_inplace(std::vector<uint8_t>& table_data, int version) {
    const uint32_t* keys = (version <= 3) ? OLD_KEYS : NEW_KEYS;
    decrypt_table_memoryfile2_inplace(table_data, keys[0], keys[1], keys[2]);
}

static void encrypt_cmf_table_inplace(std::vector<uint8_t>& table_data, int version) {
    const uint32_t* keys = (version <= 3) ? OLD_KEYS : NEW_KEYS;
    encrypt_table_memoryfile2_inplace(table_data, keys[0], keys[1], keys[2]);
}

static int detect_version(const std::vector<uint8_t>& header) {
    if (header.size() < 36) throw std::runtime_error("文件太小");
    const uint16_t ver_short = uint16_t(header[34]) | (uint16_t(header[35]) << 8);
    for (const auto& kv : VERSION_MARK) if (kv.second == ver_short) return kv.first;
    throw std::runtime_error("未知 CMF 版本标记");
}

static uint32_t decrypt_file_count(uint32_t enc_count) {
    uint32_t swap_val = ((enc_count << 24) & 0xFF000000) |
        ((enc_count >> 0) & 0x0000FF00) |
        ((enc_count << 0) & 0x00FF0000) |
        ((enc_count >> 24) & 0x000000FF);
    return swap_val ^ FILE_COUNT_KEY;
}

static uint32_t encrypt_file_count(uint32_t count) {
    uint32_t xored = count ^ FILE_COUNT_KEY;
    return ((xored << 24) & 0xFF000000) |
        ((xored >> 0) & 0x0000FF00) |
        ((xored << 0) & 0x00FF0000) |
        ((xored >> 24) & 0x000000FF);
}

struct CmfEntry {
    std::string name;
    uint32_t size = 0;
    uint32_t zsize = 0;
    uint32_t offset = 0;
    uint32_t flag = 0;
    bool is_compressed = false;
    std::vector<uint8_t> raw_data;
};

static std::vector<CmfEntry> parse_entries(const std::vector<uint8_t>& decrypted) {
    std::vector<CmfEntry> entries;
    for (size_t i = 0; i + ENTRY_SIZE <= decrypted.size(); i += ENTRY_SIZE) {
        const uint8_t* entry_buf = decrypted.data() + i;
        size_t null_pos = 512;
        for (size_t j = 0; j + 1 < 512; j += 2) {
            if (entry_buf[j] == 0 && entry_buf[j + 1] == 0) { null_pos = j; break; }
        }
        std::string name = utf16le_to_utf8(entry_buf, null_pos);
        if (name.empty()) continue;
        CmfEntry ent;
        ent.name = name;
        ent.size = read_u32_le(entry_buf + 512);
        ent.zsize = read_u32_le(entry_buf + 516);
        ent.offset = read_u32_le(entry_buf + 520);
        ent.flag = read_u32_le(entry_buf + 524);
        entries.push_back(std::move(ent));
    }
    return entries;
}

static std::vector<uint8_t> build_entries(const std::vector<CmfEntry>& entries) {
    std::vector<uint8_t> table;
    table.reserve(entries.size() * ENTRY_SIZE);
    for (const auto& ent : entries) {
        std::vector<uint8_t> name_bytes = utf8_to_utf16le(ent.name);
        if (name_bytes.size() > 512) throw std::runtime_error("文件名过长: " + ent.name);
        const size_t base = table.size();
        table.resize(base + ENTRY_SIZE, 0);
        uint8_t* entry_buf = table.data() + base;
        std::memcpy(entry_buf, name_bytes.data(), name_bytes.size());
        write_u32_le(entry_buf + 512, ent.size);
        write_u32_le(entry_buf + 516, ent.zsize);
        write_u32_le(entry_buf + 520, ent.offset);
        write_u32_le(entry_buf + 524, ent.flag);
    }
    return table;
}

static std::string safe_filename(std::string name) {
    if (name.empty()) return {};
    const size_t null_idx = name.find('\0');
    if (null_idx != std::string::npos) name.resize(null_idx);
    std::string cleaned;
    for (char c : name) {
        const unsigned char uc = static_cast<unsigned char>(c);
        if (uc >= 32 || c == '/' || c == '\\' || c == '.' || c == '_' || c == '-' || c == ' ') cleaned += c;
    }
    while (!cleaned.empty() && (cleaned.front() == '/' || cleaned.front() == '\\')) cleaned.erase(cleaned.begin());
    return cleaned;
}

static std::vector<uint8_t> decompress_data(const uint8_t* data, size_t zsize, size_t size) {
    std::vector<uint8_t> out(size);
    uLongf destLen = static_cast<uLongf>(size);
    const int rc = uncompress(out.data(), &destLen, data, static_cast<uLong>(zsize));
    if (rc == Z_OK) { out.resize(destLen); return out; }
    return std::vector<uint8_t>(data, data + zsize);
}

static std::vector<uint8_t> compress_data(const std::vector<uint8_t>& in) {
    uLongf destLen = compressBound(static_cast<uLong>(in.size()));
    std::vector<uint8_t> out(destLen);
    if (compress(out.data(), &destLen, in.data(), static_cast<uLong>(in.size())) == Z_OK) {
        out.resize(destLen);
        return out;
    }
    return in;
}

struct ParsedCMF {
    int version = 0;
    std::vector<uint8_t> original_header;
    std::vector<CmfEntry> entries;
    uint32_t version_offset = 0;
    std::vector<uint8_t> padding;
};

static std::vector<uint8_t> read_binary_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) throw std::runtime_error("无法打开文件");
    f.seekg(0, std::ios::end);
    const std::streamoff end = f.tellg();
    if (end < 0) throw std::runtime_error("无法读取文件大小");
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> data(static_cast<size_t>(end));
    if (!data.empty()) f.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!f && !data.empty()) throw std::runtime_error("读取文件失败");
    return data;
}

static int unpack_single_cmf(const fs::path& cmf_path, const fs::path& output_dir, const std::set<std::string>& allowed_exts,
    const std::function<void(int, const std::wstring&)>& progress,
    const std::function<void(const std::wstring&)>& log) {
    const auto data = read_binary_file(cmf_path);
    const int version = detect_version(data);
    if (data.size() < HEADER_SIZE) throw std::runtime_error("CMF 头部不完整");

    const uint32_t file_count = decrypt_file_count(read_u32_le(data.data() + 0x64));
    if (file_count == 0 || file_count > 50000) throw std::runtime_error("文件数量异常: " + std::to_string(file_count));

    const uint64_t table_size64 = uint64_t(file_count) * ENTRY_SIZE;
    if (table_size64 > data.size() || TABLE_OFFSET + table_size64 > data.size()) throw std::runtime_error("索引表越界");
    const uint32_t table_size = static_cast<uint32_t>(table_size64);
    const uint32_t data_start = HEADER_SIZE + table_size;
    const uint32_t version_offset = (version >= 3) ? uint32_t(version) : 0;
    if (uint64_t(data_start) + version_offset > data.size()) throw std::runtime_error("数据区起点越界");

    std::vector<uint8_t> table_data(data.begin() + TABLE_OFFSET, data.begin() + TABLE_OFFSET + table_size);
    decrypt_cmf_table_inplace(table_data, version);
    const auto entries = parse_entries(table_data);

    int count = 0;
    for (size_t idx = 0; idx < entries.size(); ++idx) {
        const auto& ent = entries[idx];
        std::string name = safe_filename(ent.name);
        if (name.empty()) continue;
        fs::path rel = fs::path(widen_utf8(name));
        const std::string ext = to_lower(narrow_utf8(rel.extension().wstring()));
        if (!allowed_exts.empty() && allowed_exts.find(ext) == allowed_exts.end()) continue;

        const uint64_t offset64 = uint64_t(ent.offset) + data_start + version_offset;
        if (offset64 >= data.size()) continue;
        const size_t offset = static_cast<size_t>(offset64);

        fs::path out_path = output_dir / rel;
        fs::create_directories(out_path.parent_path());
        std::ofstream fout(out_path, std::ios::binary);
        if (!fout) continue;

        bool wrote = false;
        if (ent.flag == 0 ||
            (ent.flag == 1 && offset + 4 <= data.size() && std::memcmp(data.data() + offset, "\x89PNG", 4) == 0) ||
            (ent.flag != 1 && ent.flag != 2 && ent.flag != 3)) {
            const size_t write_size = (ent.flag == 0 || ent.flag == 1) ? ent.size : ent.zsize;
            if (offset + write_size <= data.size()) {
                fout.write(reinterpret_cast<const char*>(data.data() + offset), static_cast<std::streamsize>(write_size));
                wrote = bool(fout);
            }
        }
        else if (offset + ent.zsize <= data.size()) {
            auto raw = decompress_data(data.data() + offset, ent.zsize, ent.size);
            fout.write(reinterpret_cast<const char*>(raw.data()), static_cast<std::streamsize>(raw.size()));
            wrote = bool(fout);
        }
        if (wrote) ++count;
        const int p = entries.empty() ? 100 : static_cast<int>(((idx + 1) * 100ull) / entries.size());
        if (progress) progress(p, std::wstring(L"正在解包：") + cmf_path.filename().wstring());
    }
    if (log) {
        std::wstringstream ss;
        ss << L"完成：" << cmf_path.filename().wstring() << L"，版本 V" << version << L"，输出 " << count << L" 个文件";
        log(ss.str());
    }
    return count;
}

static ParsedCMF read_all_entries_with_data(const fs::path& cmf_path) {
    const auto data = read_binary_file(cmf_path);
    if (data.size() < HEADER_SIZE) throw std::runtime_error("CMF 头部不完整");
    ParsedCMF cmf;
    cmf.version = detect_version(data);
    const uint32_t file_count = decrypt_file_count(read_u32_le(data.data() + 0x64));
    if (file_count == 0 || file_count > 50000) throw std::runtime_error("文件数量异常");
    const uint64_t table_size64 = uint64_t(file_count) * ENTRY_SIZE;
    if (TABLE_OFFSET + table_size64 > data.size()) throw std::runtime_error("索引表越界");
    const uint32_t table_size = static_cast<uint32_t>(table_size64);
    const uint32_t data_start = HEADER_SIZE + table_size;
    cmf.version_offset = (cmf.version >= 3) ? uint32_t(cmf.version) : 0;
    if (uint64_t(data_start) + cmf.version_offset > data.size()) throw std::runtime_error("数据区越界");
    if (cmf.version_offset > 0) cmf.padding.assign(data.begin() + data_start, data.begin() + data_start + cmf.version_offset);

    std::vector<uint8_t> table_data(data.begin() + TABLE_OFFSET, data.begin() + TABLE_OFFSET + table_size);
    decrypt_cmf_table_inplace(table_data, cmf.version);
    cmf.entries = parse_entries(table_data);
    cmf.original_header.assign(data.begin(), data.begin() + HEADER_SIZE);

    for (auto& ent : cmf.entries) {
        const uint64_t offset64 = uint64_t(data_start) + ent.offset + cmf.version_offset;
        if (offset64 + ent.size > data.size() && offset64 + ent.zsize > data.size())
            throw std::runtime_error("CMF 条目数据越界: " + ent.name);
        const size_t offset = static_cast<size_t>(offset64);
        if (ent.flag == 0 || ent.zsize == ent.size ||
            (ent.flag == 1 && offset + 4 <= data.size() && std::memcmp(data.data() + offset, "\x89PNG", 4) == 0)) {
            ent.is_compressed = false;
            if (offset + ent.size <= data.size()) ent.raw_data.assign(data.begin() + offset, data.begin() + offset + ent.size);
        }
        else if (ent.flag == 1 || ent.flag == 2) {
            ent.is_compressed = true;
            if (offset + ent.zsize <= data.size()) ent.raw_data = decompress_data(data.data() + offset, ent.zsize, ent.size);
        }
        else {
            ent.is_compressed = false;
            if (offset + ent.size <= data.size()) ent.raw_data.assign(data.begin() + offset, data.begin() + offset + ent.size);
        }
    }
    return cmf;
}

static std::vector<uint8_t> rebuild_cmf(const ParsedCMF& cmf, const std::map<std::string, std::vector<uint8_t>>& replaced_map) {
    std::vector<CmfEntry> new_entries = cmf.entries;
    for (auto& ne : new_entries) {
        const auto it = replaced_map.find(ne.name);
        const std::vector<uint8_t>& raw_data = (it != replaced_map.end()) ? it->second : ne.raw_data;
        ne.size = static_cast<uint32_t>(raw_data.size());
        if (!ne.is_compressed) {
            ne.raw_data = raw_data;
            ne.zsize = static_cast<uint32_t>(raw_data.size());
        }
        else {
            ne.raw_data = compress_data(raw_data);
            ne.zsize = static_cast<uint32_t>(ne.raw_data.size());
        }
    }

    std::vector<uint8_t> data_section = cmf.padding;
    uint32_t offset = 0;
    for (auto& ne : new_entries) {
        ne.offset = offset;
        data_section.insert(data_section.end(), ne.raw_data.begin(), ne.raw_data.end());
        offset += ne.zsize;
        ne.raw_data.clear();
        ne.raw_data.shrink_to_fit();
    }

    std::vector<uint8_t> table_data = build_entries(new_entries);
    encrypt_cmf_table_inplace(table_data, cmf.version);
    std::vector<uint8_t> final_cmf = cmf.original_header;
    write_u32_le(final_cmf.data() + 0x64, encrypt_file_count(static_cast<uint32_t>(new_entries.size())));
    final_cmf.insert(final_cmf.end(), table_data.begin(), table_data.end());
    final_cmf.insert(final_cmf.end(), data_section.begin(), data_section.end());
    return final_cmf;
}

static int repack_cmf_rebuild(const fs::path& cmf_path, const std::map<std::string, std::vector<uint8_t>>& pak_files,
    const std::function<void(const std::wstring&)>& log) {
    ParsedCMF cmf = read_all_entries_with_data(cmf_path);
    std::map<std::string, std::string> name_lower_map;
    for (const auto& ent : cmf.entries) name_lower_map[to_lower(normalize_path_utf8(ent.name))] = ent.name;

    std::map<std::string, std::vector<uint8_t>> matched_pak;
    for (const auto& kv : pak_files) {
        const std::string lower = to_lower(normalize_path_utf8(kv.first));
        auto it = name_lower_map.find(lower);
        if (it != name_lower_map.end()) matched_pak[it->second] = kv.second;
        else if (log) log(L"警告：pak 中的文件未在 CMF 找到：" + widen_utf8(kv.first));
    }

    int replace_count = 0;
    for (const auto& ent : cmf.entries) {
        auto it = matched_pak.find(ent.name);
        if (it != matched_pak.end() && it->second != ent.raw_data) {
            ++replace_count;
            if (log) {
                std::wstringstream ss;
                ss << L"替换：" << widen_utf8(ent.name) << L" (" << ent.raw_data.size() << L" -> " << it->second.size() << L" bytes)";
                log(ss.str());
            }
        }
    }
    if (replace_count == 0) {
        if (log) log(L"没有文件需要替换");
        return 0;
    }

    const fs::path bak_dir = app_root() / L"bak";
    fs::create_directories(bak_dir);
    const fs::path bak_path = bak_dir / cmf_path.filename();
    if (!fs::exists(bak_path)) {
        fs::copy_file(cmf_path, bak_path);
        if (log) log(L"原始 CMF 已备份：" + bak_path.wstring());
    }

    auto new_cmf = rebuild_cmf(cmf, matched_pak);
    std::ofstream out(cmf_path, std::ios::binary);
    if (!out) throw std::runtime_error("无法写入 CMF");
    out.write(reinterpret_cast<const char*>(new_cmf.data()), static_cast<std::streamsize>(new_cmf.size()));
    if (!out) throw std::runtime_error("写入 CMF 失败");
    if (log) {
        std::wstringstream ss;
        ss << L"封包完成：" << cmf_path.filename().wstring() << L"，替换 " << replace_count << L" 个文件";
        log(ss.str());
    }
    return replace_count;
}

// ------------------------------------------------------------
// Config
// ------------------------------------------------------------
struct Config {
    fs::path game_path;
    fs::path output_dir;
};

static fs::path exe_dir() {
    wchar_t buf[MAX_PATH]{};
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    return fs::path(std::wstring(buf, buf + n)).parent_path();
}

static fs::path app_root() {
    return exe_dir();
}

static Config load_config() {
    Config cfg;
    cfg.output_dir = app_root() / L"unpack";
    std::ifstream f(app_root() / L"config.ini");
    if (!f) return cfg;
    std::string line;
    while (std::getline(f, line)) {
        const size_t p = line.find('=');
        if (p == std::string::npos) continue;
        std::string key = line.substr(0, p);
        std::string value = line.substr(p + 1);
        if (key == "game_path") cfg.game_path = fs::path(widen_utf8(normalize_path_utf8(value)));
        else if (key == "output_dir") cfg.output_dir = fs::path(widen_utf8(normalize_path_utf8(value)));
    }
    return cfg;
}

static void save_config(const Config& cfg) {
    std::ofstream f(app_root() / L"config.ini", std::ios::trunc);
    f << "game_path=" << narrow_utf8(cfg.game_path.wstring()) << "\n";
    f << "output_dir=" << narrow_utf8(cfg.output_dir.wstring()) << "\n";
}

// ------------------------------------------------------------
// GUI
// ------------------------------------------------------------
constexpr UINT WM_APP_LOG = WM_APP + 1;
constexpr UINT WM_APP_PROGRESS = WM_APP + 2;
constexpr UINT WM_APP_OPERATION_DONE = WM_APP + 3;
constexpr UINT WM_APP_OPERATION_ERROR = WM_APP + 4;
constexpr int IDC_BTN_UNPACK_CMF = 1001;
constexpr int IDC_BTN_UNPACK_DAT = 1002;
constexpr int IDC_BTN_REPACK = 1003;
constexpr int IDC_BTN_GAME_PATH = 1004;
constexpr int IDC_BTN_OUTPUT = 1005;
constexpr int IDC_EDIT_GAME = 1101;
constexpr int IDC_EDIT_OUTPUT = 1102;
constexpr int IDC_EDIT_DROP = 1103;
constexpr int IDC_LOG = 1201;
constexpr int IDC_STATUS = 1202;
constexpr int IDC_SLIDER_START = 1204;
constexpr int IDC_SLIDER_END = 1205;
constexpr int IDC_LABEL_START = 1206;
constexpr int IDC_LABEL_END = 1207;
constexpr int IDC_EDIT_START = 1208;
constexpr int IDC_EDIT_END = 1209;

struct AppState {
    HWND hwnd = nullptr;
    HWND editGame = nullptr;
    HWND editOutput = nullptr;
    HWND editDrop = nullptr;
    HWND log = nullptr;
    HWND status = nullptr;
    int progressValue = 0; // progress 0-100, drawn by main window
    int lastDrawnProgress = -1; // 上次绘制的进度值，用于节流
    HWND sliderStart = nullptr;    // 起始范围滑块
    HWND valueStart = nullptr;     // 起始数值显示（只读）
    HWND sliderEnd = nullptr;      // 结束范围滑块
    HWND valueEnd = nullptr;       // 结束数值显示（只读）
    HWND labelStart = nullptr;
    HWND labelEnd = nullptr;
    int datRangeMax = 0;
    bool busy = false;
    Config config;
    std::vector<std::wstring> dropped;
    // 动画相关
    double anim_phase = 0.0; // 动画相位（像素）
    uint64_t anim_last_tick = 0; // 毫秒时间戳
};

static AppState g;
static ULONG_PTR g_gdiplus_token = 0;
static HFONT g_font = nullptr;
static HFONT g_font_bold = nullptr;
static HBRUSH g_bg_brush = nullptr; // 用于为静态控件提供不透明背景，避免重影

static Gdiplus::Image* g_logo = nullptr;
static Gdiplus::Image* g_btn_cmf = nullptr;
static Gdiplus::Image* g_btn_dat = nullptr;
static Gdiplus::Image* g_btn_repack = nullptr;
static Gdiplus::Image* g_progress_bg = nullptr;
static Gdiplus::Image* g_progress_fill = nullptr;
static Gdiplus::Image* g_progress_anim1 = nullptr; // 进度动画图片 A
static Gdiplus::Image* g_progress_anim2 = nullptr; // 进度动画图片 B
static Gdiplus::Image* g_progress_anim3 = nullptr; // 进度动画图片 C
static Gdiplus::Image* g_progress_anim4 = nullptr; // 进度动画图片 D
static Gdiplus::Image* g_progress_done = nullptr;  // 完成时显示的图片

// 日志批量处理队列，避免大量 PostMessage 导致消息队列拥堵和 UI 延迟
static std::mutex g_log_mutex;
static std::deque<std::wstring*> g_log_queue;
// 进度合并机制：将高频进度更新合并为最新值并减少 PostMessage 次数
static std::mutex g_progress_mutex;
static std::atomic<bool> g_progress_posted(false);
static int g_pending_progress_value = 0;
static std::wstring g_pending_progress_text;
// 解包时抑制中间日志（仅 show 完成或失败提示）
static std::atomic<bool> g_suppress_unpack_logs(false);

static COLORREF RGBX(BYTE r, BYTE gg, BYTE b) { return RGB(r, gg, b); }

static std::wstring asset_path(const wchar_t* name) { return (app_root() / L"assets" / name).wstring(); }

static Image* load_image_asset(const wchar_t* name) {
    const std::wstring p = asset_path(name);
    Image* img = Image::FromFile(p.c_str(), FALSE);
    if (img && img->GetLastStatus() == Ok) return img;
    delete img;
    return nullptr;
}

static void append_log(const std::wstring& text) {
    if (!g.log) return;
    const SYSTEMTIME st = [] { SYSTEMTIME x{}; GetLocalTime(&x); return x; }();
    wchar_t prefix[64]{};
    StringCchPrintfW(prefix, _countof(prefix), L"[%02u:%02u:%02u] ", st.wHour, st.wMinute, st.wSecond);
    std::wstring line = prefix + text + L"\r\n";
    const int len = GetWindowTextLengthW(g.log);
    SendMessageW(g.log, EM_SETSEL, len, len);
    SendMessageW(g.log, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(line.c_str()));
    SendMessageW(g.log, WM_VSCROLL, SB_BOTTOM, 0);
    // 标记日志控件需要重绘，实际重绘由消息循环自然处理以减少卡顿
    RedrawWindow(g.log, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE);
}

static void gui_log(const std::wstring& text) {
    // 在解包操作期间可抑制中间日志输出
    if (g_suppress_unpack_logs.load()) return;
    auto* s = new std::wstring(text);
    bool shouldPost = false;
    {
        std::lock_guard<std::mutex> lk(g_log_mutex);
        g_log_queue.push_back(s);
        // 仅当队列之前为空时发送一个 WM_APP_LOG，用于唤醒主线程并一次性处理所有积累的日志
        if (g_log_queue.size() == 1) shouldPost = true;
    }
    if (shouldPost) {
        if (!PostMessageW(g.hwnd, WM_APP_LOG, 0, 0)) {
            // 如果发送失败，直接清理并删除刚推入的项
            std::lock_guard<std::mutex> lk(g_log_mutex);
            while (!g_log_queue.empty()) { delete g_log_queue.front(); g_log_queue.pop_front(); }
        }
    }
}

struct ProgressPacket { int value; std::wstring text; };

static void gui_progress(int value, const std::wstring& text) {
    int v = std::clamp(value, 0, 100);
    bool shouldPost = false;
    {
        std::lock_guard<std::mutex> lk(g_progress_mutex);
        g_pending_progress_value = v;
        g_pending_progress_text = text;
        // 只有当未有待处理的消息时才 PostMessage
        if (!g_progress_posted.exchange(true)) {
            shouldPost = true;
        }
    }
    if (shouldPost) {
        if (!PostMessageW(g.hwnd, WM_APP_PROGRESS, 0, 0)) {
            // 如果发送失败，清理 posted 标志以允许后续更新重新发送
            g_progress_posted.store(false);
        }
    }
}

static void set_busy(bool busy) {
    g.busy = busy;
    EnableWindow(GetDlgItem(g.hwnd, IDC_BTN_UNPACK_CMF), !busy);
    EnableWindow(GetDlgItem(g.hwnd, IDC_BTN_UNPACK_DAT), !busy);
    EnableWindow(GetDlgItem(g.hwnd, IDC_BTN_REPACK), !busy);
    EnableWindow(GetDlgItem(g.hwnd, IDC_BTN_GAME_PATH), !busy);
    EnableWindow(GetDlgItem(g.hwnd, IDC_BTN_OUTPUT), !busy);
    // 启动/停止进度条动画定时器（主线程调用）
    if (g.hwnd) {
        const UINT_PTR TIMER_ID = 0xC0DE;
        if (busy) {
            // 16ms 刷新，尽量接近 60 FPS 提升动画流畅度
            g.anim_last_tick = GetTickCount64();
            SetTimer(g.hwnd, TIMER_ID, 16, nullptr);
        } else {
            KillTimer(g.hwnd, TIMER_ID);
        }
    }
}

static std::wstring edit_text(HWND h) {
    const int n = GetWindowTextLengthW(h);
    std::wstring s(n, L'\0');
    if (n) GetWindowTextW(h, s.data(), n + 1);
    return s;
}

static void set_edit(HWND h, const std::wstring& s) { SetWindowTextW(h, s.c_str()); }

static void set_status(const std::wstring& s) { if (g.status) SetWindowTextW(g.status, s.c_str()); }

static int detect_max_dat_number(const fs::path& game_dir) {
    const fs::path dat_dir = game_dir / L"DAT";
    if (!fs::is_directory(dat_dir)) return 0;
    int max_num = 0;
    for (const auto& e : fs::directory_iterator(dat_dir)) {
        const std::wstring name = e.path().filename().wstring();
        if (e.is_directory() && name.size() >= 4 && _wcsnicmp(name.c_str(), L"DAT", 3) == 0) {
            bool digits = true;
            for (size_t i = 3; i < name.size(); ++i) 
                if (name[i] < L'0' || name[i] > L'9') digits = false;
            if (digits) {
                int num = std::stoi(name.substr(3));
                max_num = std::max(max_num, num);
            }
        }
    }
    return max_num;
}

static void update_dat_range_sliders() {
    const std::wstring game_path = edit_text(g.editGame);
    if (game_path.empty()) return;

    const int max_num = detect_max_dat_number(fs::path(game_path));
    if (max_num <= 0) {
        g.datRangeMax = 0;
        // 禁用滑块
        EnableWindow(g.sliderStart, FALSE);
        EnableWindow(g.sliderEnd, FALSE);
        SetWindowTextW(g.labelStart, L"起始: 0");
        SetWindowTextW(g.labelEnd, L"结束: 0");
        SetWindowTextW(g.valueStart, L"0");
        SetWindowTextW(g.valueEnd, L"0");
        return;
    }

    g.datRangeMax = max_num;
    // 启用滑块
    EnableWindow(g.sliderStart, TRUE);
    EnableWindow(g.sliderEnd, TRUE);

    SendMessageW(g.sliderStart, TBM_SETRANGE, TRUE, MAKELPARAM(0, max_num));
    SendMessageW(g.sliderEnd, TBM_SETRANGE, TRUE, MAKELPARAM(0, max_num));
    SendMessageW(g.sliderStart, TBM_SETPOS, TRUE, 0);
    SendMessageW(g.sliderEnd, TBM_SETPOS, TRUE, max_num);

    wchar_t buf[64];
    StringCchPrintfW(buf, _countof(buf), L"%d", 0);
    SetWindowTextW(g.valueStart, buf);
    StringCchPrintfW(buf, _countof(buf), L"%d", max_num);
    SetWindowTextW(g.valueEnd, buf);
    StringCchPrintfW(buf, _countof(buf), L"起始: %d", 0);
    SetWindowTextW(g.labelStart, buf);
    StringCchPrintfW(buf, _countof(buf), L"结束: %d", max_num);
    SetWindowTextW(g.labelEnd, buf);
}


static bool browse_folder(HWND owner, fs::path& out, const wchar_t* title) {
    IFileDialog* dialog = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog));
    if (FAILED(hr)) return false;
    DWORD options = 0;
    dialog->GetOptions(&options);
    dialog->SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM);
    dialog->SetTitle(title);
    bool ok = false;
    if (SUCCEEDED(dialog->Show(owner))) {
        IShellItem* item = nullptr;
        if (SUCCEEDED(dialog->GetResult(&item))) {
            PWSTR p = nullptr;
            if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &p)) && p) {
                out = fs::path(p);
                CoTaskMemFree(p);
                ok = true;
            }
            item->Release();
        }
    }
    dialog->Release();
    return ok;
}

static bool message_confirm(const std::wstring& text, const std::wstring& title) {
    return MessageBoxW(g.hwnd, text.c_str(), title.c_str(), MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2) == IDYES;
}

static void update_config_from_edits() {
    g.config.game_path = fs::path(edit_text(g.editGame));
    g.config.output_dir = fs::path(edit_text(g.editOutput));
    save_config(g.config);
}

static bool is_cmf_path(const fs::path& p) { return fs::is_regular_file(p) && to_lower(narrow_utf8(p.extension().wstring())) == ".cmf"; }
static bool is_dat_dir(const fs::path& p) {
    return fs::is_directory(p) && p.filename().wstring().size() >= 3 && _wcsnicmp(p.filename().c_str(), L"DAT", 3) == 0;
}

static void identify_drop(const std::vector<std::wstring>& paths) {
    if (paths.empty()) return;
    g.dropped = paths;
    std::wstringstream ss;
    ss << L"识别拖放路径：共 " << paths.size() << L" 项";
    gui_log(ss.str());
    for (const auto& s : paths) {
        fs::path p(s);
        std::wstring type = L"未知";
        if (is_cmf_path(p)) type = L"CMF 文件";
        else if (is_dat_dir(p)) type = L"DAT 目录";
        else if (fs::is_directory(p) && fs::exists(p / L"DAT")) type = L"游戏客户端目录（包含 DAT）";
        else if (fs::is_directory(p)) type = L"目录";
        else if (fs::is_regular_file(p)) type = L"普通文件";
        gui_log(type + L"：" + p.wstring());
    }
    set_edit(g.editDrop, paths.front());
    const fs::path p(paths.front());
    if (fs::is_directory(p) && fs::exists(p / L"DAT")) {
        g.config.game_path = p;
        set_edit(g.editGame, p.wstring());
        save_config(g.config);
        set_status(L"已识别游戏客户端目录");
    }
    else if (is_dat_dir(p)) {
        g.config.game_path = p.parent_path().parent_path();
        set_edit(g.editGame, g.config.game_path.wstring());
        save_config(g.config);
        set_status(L"已识别 DAT 目录");
    }
    else if (is_cmf_path(p)) {
        set_status(L"已识别 CMF 文件，可用于查看路径；批量操作仍使用 cmf 目录");
    }
}

static void run_unpack_cmf_folder() {
    try {
        // 在整个解包操作期间抑制中间日志输出，避免消息洪泛
        g_suppress_unpack_logs.store(true);
        const fs::path cmf_dir = app_root() / L"cmf";
        const fs::path out_dir = fs::path(edit_text(g.editOutput));
        fs::create_directories(cmf_dir);
        fs::create_directories(out_dir);
        std::vector<fs::path> cmfs;
        for (const auto& e : fs::directory_iterator(cmf_dir)) if (to_lower(narrow_utf8(e.path().extension().wstring())) == ".cmf") cmfs.push_back(e.path());
        std::sort(cmfs.begin(), cmfs.end());
        if (cmfs.empty()) {
            gui_log(L"cmf 目录中没有 .cmf 文件。目录已自动创建：" + cmf_dir.wstring());
            set_status(L"等待 CMF 文件");
            return;
        }
        const bool group = message_confirm(L"输出是否按 CMF 文件名分文件夹？\n\n选择“否”将直接输出到指定目录。", L"CMF 解包设置");
        const auto start = std::chrono::steady_clock::now();
        int total = 0;
        for (size_t i = 0; i < cmfs.size(); ++i) {
            const fs::path out = group ? (out_dir / cmfs[i].filename()) : out_dir;
            gui_log(L"开始处理：" + cmfs[i].filename().wstring());
            const int n = unpack_single_cmf(cmfs[i], out, {},
                [&](int inner, const std::wstring& t) {
                    const int overall = static_cast<int>(((i * 100ull) + inner) / cmfs.size());
                    gui_progress(overall, t);
                }, gui_log);
            total += n;
            gui_progress(static_cast<int>(((i + 1) * 100ull) / cmfs.size()), L"CMF 批处理完成");
        }
        const int seconds = static_cast<int>(std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count());
        // 取消抑制，允许显示完成提示
        g_suppress_unpack_logs.store(false);
        // 分隔线和明显的完成提示
        gui_log(L"=================================");

        std::wstringstream ss;
        ss << L"✓ CMF 目录解包全部完成!";
        gui_log(ss.str());

        std::wstringstream ss2;
        ss2 << L"  · 输出文件数：" << total << L" 个";
        gui_log(ss2.str());

        std::wstringstream ss3;
        ss3 << L"  · 总耗时：" << seconds << L" 秒";
        gui_log(ss3.str());

        gui_log(L"=================================");

        set_status(L"CMF 解包完成");
    }
    catch (const std::exception& e) {
        // 发生异常时取消抑制以显示失败信息
        g_suppress_unpack_logs.store(false);
        gui_log(L"CMF 解包失败：" + widen_utf8(e.what()));
        set_status(L"操作失败");
    }
}

static std::vector<std::string> parse_dat_selection(int max_num_hint) {
    std::wstring inp = edit_text(g.editDrop);
    std::string s = narrow_utf8(inp);
    std::vector<std::string> ret;
    if (s.empty()) return ret;
    const size_t dash = s.find('-');
    try {
        if (dash != std::string::npos) {
            int a = std::stoi(s.substr(0, dash));
            int b = std::stoi(s.substr(dash + 1));
            if (a > b) std::swap(a, b);
            a = std::max<int>(0, a);
            if (max_num_hint >= 0) b = std::min<int>(max_num_hint, b);
            for (int i = a; i <= b; ++i) ret.push_back("DAT" + std::to_string(i));
        }
        else {
            int x = std::stoi(s);
            if (x >= 0 && (max_num_hint < 0 || x <= max_num_hint)) ret.push_back("DAT" + std::to_string(x));
        }
    }
    catch (...) {}
    return ret;
}

static void run_unpack_dat() {
    try {
        // 在整个解包操作期间抑制中间日志输出，避免消息洪泛
        g_suppress_unpack_logs.store(true);
        fs::path game = fs::path(edit_text(g.editGame));
        if (!fs::is_directory(game)) {
            if (!browse_folder(g.hwnd, game, L"请选择游戏客户端根目录（应包含 DAT 文件夹）")) return;
            set_edit(g.editGame, game.wstring());
        }
        const fs::path dat_dir = game / L"DAT";
        if (!fs::is_directory(dat_dir)) throw std::runtime_error("找不到 DAT 文件夹：" + narrow_utf8(dat_dir.wstring()));

        std::vector<std::string> folders;
        for (const auto& e : fs::directory_iterator(dat_dir)) {
            const std::wstring name = e.path().filename().wstring();
            if (e.is_directory() && name.size() >= 4 && _wcsnicmp(name.c_str(), L"DAT", 3) == 0) {
                bool digits = true;
                for (size_t i = 3; i < name.size(); ++i) if (name[i] < L'0' || name[i] > L'9') digits = false;
                if (digits) folders.push_back(narrow_utf8(name));
            }
        }
        std::sort(folders.begin(), folders.end(), [](const std::string& a, const std::string& b) {
            return std::stoi(a.substr(3)) < std::stoi(b.substr(3));
            });
        if (folders.empty()) throw std::runtime_error("DAT 文件夹为空");

        // 从滑块获取范围
        int startRange = (int)SendMessageW(g.sliderStart, TBM_GETPOS, 0, 0);
        int endRange = (int)SendMessageW(g.sliderEnd, TBM_GETPOS, 0, 0);

        if (g.datRangeMax <= 0) {
            MessageBoxW(g.hwnd, L"请先选择有效的游戏目录，系统会自动检测 DAT 范围。", L"DAT 解压", MB_ICONWARNING);
            return;
        }

        // 构建目标DAT列表
        std::vector<std::string> targets;
        for (const auto& folder : folders) {
            int num = std::stoi(folder.substr(3));
            if (num >= startRange && num <= endRange) {
                targets.push_back(folder);
            }
        }

        if (targets.empty()) throw std::runtime_error("选定范围内没有 DAT 文件夹");

        std::wstringstream info;
        info << L"即将解压 DAT" << startRange << L" ~ DAT" << endRange 
             << L"，共 " << targets.size() << L" 个文件夹。\n\n继续吗？";
        if (MessageBoxW(g.hwnd, info.str().c_str(), L"确认 DAT 解压", MB_ICONQUESTION | MB_YESNO) != IDYES) {
            return;
        }

        const fs::path outdir = fs::path(edit_text(g.editOutput));
        fs::create_directories(outdir);
        const bool group = message_confirm(L"输出是否按 DAT / CMF 分目录？\n\n选择“否”将直接输出到 DAT 目录。", L"DAT 解压设置");

        size_t total_cmf = 0;
        std::vector<std::pair<fs::path, fs::path>> work;
        for (const auto& dat_name : targets) {
            const fs::path dat_path = dat_dir / widen_utf8(dat_name);
            if (!fs::is_directory(dat_path)) continue;
            for (const auto& e : fs::directory_iterator(dat_path)) {
                if (e.is_regular_file() && to_lower(narrow_utf8(e.path().extension().wstring())) == ".cmf") {
                    fs::path target = group ? (outdir / widen_utf8(dat_name) / e.path().filename()) : (outdir / widen_utf8(dat_name));
                    work.emplace_back(e.path(), target);
                }
            }
        }
        total_cmf = work.size();
        if (!total_cmf) throw std::runtime_error("所选 DAT 中没有 CMF 文件");

        const auto start = std::chrono::steady_clock::now();
        int total_files = 0;
        for (size_t i = 0; i < work.size(); ++i) {
            fs::create_directories(work[i].second);
            gui_log(L"处理：" + work[i].first.wstring());
            const int n = unpack_single_cmf(work[i].first, work[i].second, {},
                [&](int inner, const std::wstring& t) {
                    const int overall = static_cast<int>(((i * 100ull) + inner) / total_cmf);
                    gui_progress(overall, t);
                }, gui_log);
            total_files += n;
            gui_progress(static_cast<int>(((i + 1) * 100ull) / total_cmf), L"DAT 批处理进度");
        }
        const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
        // 取消抑制，允许显示完成提示
        g_suppress_unpack_logs.store(false);
        // 分隔线和明显的完成提示
        gui_log(L"=================================");

        std::wstringstream ss;
        ss << L"✓ 客户端 DAT 解压全部完成!";
        gui_log(ss.str());

        std::wstringstream ss2;
        ss2 << L"  · 处理 CMF 数:" << total_cmf << L" 个";
        gui_log(ss2.str());

        std::wstringstream ss3;
        ss3 << L"  · 输出文件数:" << total_files << L" 个";
        gui_log(ss3.str());

        std::wstringstream ss4;
        ss4 << L"  · 总耗时:" << (int)seconds << L" 秒";
        gui_log(ss4.str());

        gui_log(L"=================================");

        // 触发主线程更新完成状态，不发送 WM_APP_PROGRESS 以免 nullptr 崩溃
        set_status(L"DAT 解压完成");
        PostMessageW(g.hwnd, WM_APP_OPERATION_DONE, 0, 0);
    }
    catch (const std::exception& e) {
        // 发生异常时取消抑制以显示失败信息
        g_suppress_unpack_logs.store(false);
        gui_log(L"DAT 解压失败：" + widen_utf8(e.what()));
        set_status(L"操作失败");
    }
}

static void run_repack() {
    try {
        const fs::path cmf_dir = app_root() / L"cmf";
        const fs::path pak_dir = app_root() / L"pak";
        if (!fs::is_directory(cmf_dir) || !fs::is_directory(pak_dir))
            throw std::runtime_error("需要同时存在程序目录下的 cmf 与 pak 文件夹");
        std::vector<fs::path> cmfs;
        for (const auto& e : fs::directory_iterator(cmf_dir)) if (to_lower(narrow_utf8(e.path().extension().wstring())) == ".cmf") cmfs.push_back(e.path());
        if (cmfs.empty()) throw std::runtime_error("cmf 文件夹中没有 .cmf 文件");

        std::map<std::string, std::vector<uint8_t>> pak_all;
        for (const auto& e : fs::recursive_directory_iterator(pak_dir)) {
            if (!e.is_regular_file()) continue;
            const std::string rel = normalize_path_utf8(narrow_utf8(fs::relative(e.path(), pak_dir).wstring()));
            pak_all[rel] = read_binary_file(e.path());
        }
        if (pak_all.empty()) throw std::runtime_error("pak 文件夹中没有文件");

        std::wstringstream info;
        info << L"准备封包：CMF " << cmfs.size() << L" 个，pak 文件 " << pak_all.size() << L" 个。\n\n确认继续？";
        if (!message_confirm(info.str(), L"CMF 封包")) return;

        const auto start = std::chrono::steady_clock::now();
        for (size_t i = 0; i < cmfs.size(); ++i) {
            gui_log(L"开始封包：" + cmfs[i].filename().wstring());
            const int replaced = repack_cmf_rebuild(cmfs[i], pak_all, gui_log);
            (void)replaced;
            gui_progress(static_cast<int>(((i + 1) * 100ull) / cmfs.size()), L"封包进度");
        }
        const int seconds = static_cast<int>(std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count());

        // 分隔线和明显的完成提示
        gui_log(L"=================================");

        std::wstringstream ss;
        ss << L"✓ 所有 CMF 封包操作完成!";
        gui_log(ss.str());

        std::wstringstream ss2;
        ss2 << L"  · 封包文件数:" << cmfs.size() << L" 个";
        gui_log(ss2.str());

        std::wstringstream ss3;
        ss3 << L"  · 总耗时:" << seconds << L" 秒";
        gui_log(ss3.str());

        gui_log(L"=================================");

        set_status(L"封包完成");
    }
    catch (const std::exception& e) {
        gui_log(L"封包失败：" + widen_utf8(e.what()));
        set_status(L"操作失败");
    }
}

static void start_operation(void(*worker)()) {
    if (g.busy) return;
    update_config_from_edits();
    set_busy(true);
    gui_progress(0, L"准备开始…");
    auto fn = worker;
    std::thread([fn]() {
        fn();
        PostMessageW(g.hwnd, WM_APP_OPERATION_DONE, 0, 0);
        }).detach();
}

static void draw_rounded_rect(Graphics& graphics, const RectF& r, REAL radius, const Color& c) {
    GraphicsPath path;
    const REAL d = radius * 2.0f;
    path.AddArc(r.X, r.Y, d, d, 180, 90);
    path.AddArc(r.GetRight() - d, r.Y, d, d, 270, 90);
    path.AddArc(r.GetRight() - d, r.GetBottom() - d, d, d, 0, 90);
    path.AddArc(r.X, r.GetBottom() - d, d, d, 90, 90);
    path.CloseFigure();
    SolidBrush b(c);
    graphics.FillPath(&b, &path);
}

static void draw_image_cover(Graphics& gr, Image* image, const RectF& dst) {
    if (!image || image->GetLastStatus() != Ok) return;
    const REAL iw = (REAL)image->GetWidth();
    const REAL ih = (REAL)image->GetHeight();
    const REAL sx = dst.Width / iw;
    const REAL sy = dst.Height / ih;
    const REAL scale = std::min(sx, sy);
    const REAL w = iw * scale;
    const REAL h = ih * scale;
    const REAL x = dst.X + (dst.Width - w) / 2.0f;
    const REAL y = dst.Y + (dst.Height - h) / 2.0f;
    gr.DrawImage(image, RectF(x, y, w, h));
}

static void paint_progress(HWND hwnd, HDC hdc) {
    RECT rc{};
    GetClientRect(hwnd, &rc);
    Graphics gr(hdc);
    RectF full(0, 0, (REAL)(rc.right - rc.left), (REAL)(rc.bottom - rc.top));
    if (g_progress_bg) draw_image_cover(gr, g_progress_bg, full);
}

class ImageButtonWnd {
public:
    HWND hwnd = nullptr;
    Image* img = nullptr;
    bool hot = false;
    bool down = false;
    int command = 0;
};

static LRESULT CALLBACK ImageButtonProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    ImageButtonWnd* b = reinterpret_cast<ImageButtonWnd*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_NCCREATE: {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        b = reinterpret_cast<ImageButtonWnd*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(b));
        b->hwnd = hwnd;
        return TRUE;
    }
    case WM_MOUSEMOVE:
        if (b && !b->hot) {
            b->hot = true;
            InvalidateRect(hwnd, nullptr, FALSE);
            TRACKMOUSEEVENT t{ sizeof(t), TME_LEAVE, hwnd, 0 };
            TrackMouseEvent(&t);
        }
        return 0;
    case WM_MOUSELEAVE:
        if (b && b->hot) {
            b->hot = false;
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        return 0;
    case WM_LBUTTONDOWN:
        if (b && !b->down) {
            b->down = true;
            SetCapture(hwnd);
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        return 0;
    case WM_LBUTTONUP:
        if (b) {
            bool click = b->down;
            b->down = false;
            ReleaseCapture();
            InvalidateRect(hwnd, nullptr, FALSE);
            if (click && g.hwnd) SendMessageW(g.hwnd, WM_COMMAND, MAKEWPARAM(b->command, BN_CLICKED), (LPARAM)hwnd);
        }
        return 0;
    case WM_ENABLE:
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps{};
        HDC dc = BeginPaint(hwnd, &ps);
        RECT rc{}; GetClientRect(hwnd, &rc);

        // 创建双缓冲以消除闪烁
        HDC memDC = CreateCompatibleDC(dc);
        HBITMAP memBitmap = CreateCompatibleBitmap(dc, rc.right, rc.bottom);
        HBITMAP oldBitmap = (HBITMAP)SelectObject(memDC, memBitmap);

        Graphics gr(memDC);
        gr.SetSmoothingMode(SmoothingModeAntiAlias);
        gr.SetInterpolationMode(InterpolationModeHighQualityBicubic);

        // 透明背景
        gr.Clear(Color(0, 0, 0, 0));

        // 绘制图片或文字
        if (b && b->img) {
            // 固定显示尺寸为 340x120，居中绘制
            REAL imgWidth = 340.0f;
            REAL imgHeight = 120.0f;
            REAL imgX = (rc.right - imgWidth) / 2.0f;
            REAL imgY = (rc.bottom - imgHeight) / 2.0f;

            // 添加轻微的按下效果（图片稍微下移）
            if (b->down) {
                imgY += 2.0f;
            }

            // 绘制图片，禁用状态时降低不透明度
            if (!IsWindowEnabled(hwnd)) {
                ColorMatrix matrix = {
                    1.0f, 0.0f, 0.0f, 0.0f, 0.0f,
                    0.0f, 1.0f, 0.0f, 0.0f, 0.0f,
                    0.0f, 0.0f, 1.0f, 0.0f, 0.0f,
                    0.0f, 0.0f, 0.0f, 0.5f, 0.0f,  // 50% 不透明度
                    0.0f, 0.0f, 0.0f, 0.0f, 1.0f
                };
                ImageAttributes attr;
                attr.SetColorMatrix(&matrix);
                gr.DrawImage(b->img, RectF(imgX, imgY, imgWidth, imgHeight), 
                    0, 0, (REAL)b->img->GetWidth(), (REAL)b->img->GetHeight(), 
                    UnitPixel, &attr);
            } else {
                gr.DrawImage(b->img, RectF(imgX, imgY, imgWidth, imgHeight));
            }
        } else {
            // 如果没有图片，显示文字（作为备选方案）
            SolidBrush textBrush(Color(255, 91, 76, 122));
            FontFamily fam(L"Microsoft YaHei UI");
            Font font(&fam, 16, FontStyleBold, UnitPixel);
            StringFormat fmt;
            fmt.SetAlignment(StringAlignmentCenter);
            fmt.SetLineAlignment(StringAlignmentCenter);

            const wchar_t* label = L"按钮";
            if (b) {
                if (b->command == IDC_BTN_UNPACK_CMF) label = L"解包 CMF";
                else if (b->command == IDC_BTN_UNPACK_DAT) label = L"解包 DAT";
                else if (b->command == IDC_BTN_REPACK) label = L"封包";
            }

            RectF textRect(0, 0, (REAL)rc.right, (REAL)rc.bottom);
            gr.DrawString(label, -1, &font, textRect, &fmt, &textBrush);
        }

        // 将双缓冲内容复制到屏幕
        BitBlt(dc, 0, 0, rc.right, rc.bottom, memDC, 0, 0, SRCCOPY);

        // 清理双缓冲资源
        SelectObject(memDC, oldBitmap);
        DeleteObject(memBitmap);
        DeleteDC(memDC);

        EndPaint(hwnd, &ps);
        return 0;
    }
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static HWND create_image_button(HWND parent, int id, RECT rc, Image* img) {
    auto* b = new ImageButtonWnd();
    b->img = img; b->command = id;
    static bool registered = false;
    if (!registered) {
        WNDCLASSW wc{};
        wc.lpfnWndProc = ImageButtonProc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.lpszClassName = L"ClosersImageButton";
        wc.hCursor = LoadCursorW(nullptr, IDC_HAND);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.hbrBackground = nullptr;  // 不使用背景画刷，改为自绘
        RegisterClassW(&wc);
        registered = true;
    }
    return CreateWindowExW(WS_EX_TRANSPARENT, L"ClosersImageButton", L"", WS_CHILD | WS_VISIBLE, rc.left, rc.top,
        rc.right - rc.left, rc.bottom - rc.top, parent, (HMENU)(INT_PTR)id, GetModuleHandleW(nullptr), b);
}

static void create_controls(HWND hwnd) {
    RECT rc{}; GetClientRect(hwnd, &rc);
    const int pad = 24;
    const int contentW = rc.right - pad * 2;

    g.editGame = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        150, 250, contentW - 270, 34, hwnd, (HMENU)(INT_PTR)IDC_EDIT_GAME, GetModuleHandleW(nullptr), nullptr);
    g.editOutput = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        150, 292, contentW - 270, 34, hwnd, (HMENU)(INT_PTR)IDC_EDIT_OUTPUT, GetModuleHandleW(nullptr), nullptr);
    g.editDrop = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        150, 334, contentW - 48, 34, hwnd, (HMENU)(INT_PTR)IDC_EDIT_DROP, GetModuleHandleW(nullptr), nullptr);

    SendMessageW(g.editGame, WM_SETFONT, (WPARAM)g_font, TRUE);
    SendMessageW(g.editOutput, WM_SETFONT, (WPARAM)g_font, TRUE);
    SendMessageW(g.editDrop, WM_SETFONT, (WPARAM)g_font, TRUE);

    auto b1 = CreateWindowW(L"BUTTON", L"选择", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, contentW - 106, 250, 82, 34, hwnd, (HMENU)(INT_PTR)IDC_BTN_GAME_PATH, GetModuleHandleW(nullptr), nullptr);
    auto b2 = CreateWindowW(L"BUTTON", L"选择", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, contentW - 106, 292, 82, 34, hwnd, (HMENU)(INT_PTR)IDC_BTN_OUTPUT, GetModuleHandleW(nullptr), nullptr);
    SendMessageW(b1, WM_SETFONT, (WPARAM)g_font, TRUE); SendMessageW(b2, WM_SETFONT, (WPARAM)g_font, TRUE);

    // DAT范围标签和滑块控件
    g.labelStart = CreateWindowExW(0, L"STATIC", L"起始: 0", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE,
        24, 380, 110, 30, hwnd, (HMENU)(INT_PTR)IDC_LABEL_START, GetModuleHandleW(nullptr), nullptr);

    // 起始滑块（TRACKBAR）
    g.sliderStart = CreateWindowExW(0, TRACKBAR_CLASSW, L"", WS_CHILD | WS_VISIBLE | TBS_HORZ | TBS_AUTOTICKS | TBS_NOTICKS,
        145, 380, 280, 30, hwnd, (HMENU)(INT_PTR)IDC_SLIDER_START, GetModuleHandleW(nullptr), nullptr);

    // 起始数值显示（只读静态文本）
    g.valueStart = CreateWindowExW(WS_EX_CLIENTEDGE, L"STATIC", L"0", WS_CHILD | WS_VISIBLE | SS_CENTER | SS_CENTERIMAGE,
        435, 380, 60, 30, hwnd, (HMENU)(INT_PTR)IDC_EDIT_START, GetModuleHandleW(nullptr), nullptr);

    g.labelEnd = CreateWindowExW(0, L"STATIC", L"结束: 0", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE,
        24, 418, 110, 30, hwnd, (HMENU)(INT_PTR)IDC_LABEL_END, GetModuleHandleW(nullptr), nullptr);

    // 结束滑块（TRACKBAR）
    g.sliderEnd = CreateWindowExW(0, TRACKBAR_CLASSW, L"", WS_CHILD | WS_VISIBLE | TBS_HORZ | TBS_AUTOTICKS | TBS_NOTICKS,
        145, 418, 280, 30, hwnd, (HMENU)(INT_PTR)IDC_SLIDER_END, GetModuleHandleW(nullptr), nullptr);

    // 结束数值显示（只读静态文本）
    g.valueEnd = CreateWindowExW(WS_EX_CLIENTEDGE, L"STATIC", L"0", WS_CHILD | WS_VISIBLE | SS_CENTER | SS_CENTERIMAGE,
        435, 418, 60, 30, hwnd, (HMENU)(INT_PTR)IDC_EDIT_END, GetModuleHandleW(nullptr), nullptr);

    SendMessageW(g.labelStart, WM_SETFONT, (WPARAM)g_font_bold, TRUE);
    SendMessageW(g.labelEnd, WM_SETFONT, (WPARAM)g_font_bold, TRUE);
    SendMessageW(g.valueStart, WM_SETFONT, (WPARAM)g_font_bold, TRUE);
    SendMessageW(g.valueEnd, WM_SETFONT, (WPARAM)g_font_bold, TRUE);

    // 初始化滑块范围并禁用
    SendMessageW(g.sliderStart, TBM_SETRANGE, TRUE, MAKELONG(0, 0));
    SendMessageW(g.sliderEnd, TBM_SETRANGE, TRUE, MAKELONG(0, 0));
    EnableWindow(g.sliderStart, FALSE);
    EnableWindow(g.sliderEnd, FALSE);

    // 尝试使用 RichEdit（Msftedit.dll）以获得更稳健的文本绘制；若不可用回退到标准 EDIT
    HWND hRich = nullptr;
    HMODULE hMsft = LoadLibraryW(L"Msftedit.dll");
    if (hMsft) {
        hRich = CreateWindowExW(WS_EX_CLIENTEDGE, L"RICHEDIT50W", L"", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
            pad, 570, contentW, 150, hwnd, (HMENU)(INT_PTR)IDC_LOG, GetModuleHandleW(nullptr), nullptr);
    }
    if (hRich) {
        g.log = hRich;
        HFONT hLogFont = CreateFontW(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
        SendMessageW(g.log, WM_SETFONT, (WPARAM)(hLogFont ? hLogFont : g_font), TRUE);
    } else {
        // 回退到普通 EDIT
        HFONT hLogFont = CreateFontW(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
        g.log = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
            pad, 570, contentW, 150, hwnd, (HMENU)(INT_PTR)IDC_LOG, GetModuleHandleW(nullptr), nullptr);
        SendMessageW(g.log, WM_SETFONT, (WPARAM)(hLogFont ? hLogFont : g_font), TRUE);
    }
    // 如果加载了 Msftedit.dll，则不立即释放，以保证类持续可用
    // 如果确实需要卸载，可在程序退出时 FreeLibrary(hMsft);

    g.status = CreateWindowW(L"STATIC", L"就绪 · 可直接拖放文件/目录到窗口", WS_CHILD | WS_VISIBLE, pad, 540, contentW, 24, hwnd, (HMENU)(INT_PTR)IDC_STATUS, GetModuleHandleW(nullptr), nullptr);
    SendMessageW(g.status, WM_SETFONT, (WPARAM)g_font_bold, TRUE);

    // 创建三个主要图片按钮
    create_image_button(hwnd, IDC_BTN_REPACK, RECT{ pad, 105, pad + 340, 225 }, g_btn_repack);
    create_image_button(hwnd, IDC_BTN_UNPACK_CMF, RECT{ pad + 356, 105, pad + 696, 225 }, g_btn_cmf);
    create_image_button(hwnd, IDC_BTN_UNPACK_DAT, RECT{ pad + 712, 105, pad + 1052, 225 }, g_btn_dat);

    set_edit(g.editGame, g.config.game_path.wstring());
    set_edit(g.editOutput, g.config.output_dir.wstring());
    DragAcceptFiles(hwnd, TRUE);

    update_dat_range_sliders();
}

static void draw_main_background(HWND hwnd, HDC hdc) {
    RECT rc{}; GetClientRect(hwnd, &rc);
    Graphics gr(hdc);
    gr.SetSmoothingMode(SmoothingModeAntiAlias);
    LinearGradientBrush bg(Point(0, 0), Point(rc.right, rc.bottom), Color(255, 255, 248, 253), Color(255, 245, 250, 255));
    gr.FillRectangle(&bg, 0, 0, rc.right, rc.bottom);

    // cute pastel decorative circles
    SolidBrush p1(Color(70, 255, 205, 230)); gr.FillEllipse(&p1, -70, 30, 230, 230);
    SolidBrush p2(Color(55, 195, 225, 255)); gr.FillEllipse(&p2, rc.right - 190, -70, 250, 250);
    SolidBrush p3(Color(40, 255, 215, 190)); gr.FillEllipse(&p3, rc.right - 170, rc.bottom - 160, 210, 210);

    if (g_logo) {
        // Logo 固定大小 1100x90，居中显示
        REAL logoWidth = 1100.0f;
        REAL logoHeight = 90.0f;
        REAL logoX = (rc.right - logoWidth) / 2.0f;
        REAL logoY = 0;
        gr.DrawImage(g_logo, RectF(logoX, logoY, logoWidth, logoHeight));
    }
    else {
        SolidBrush dark(Color(255, 74, 66, 110));
        FontFamily fam(L"Microsoft YaHei UI");
        Font f(&fam, 27.0f, FontStyleBold, UnitPixel);
        StringFormat fmt; fmt.SetAlignment(StringAlignmentCenter);
        gr.DrawString(L"Closers CMF TOOLS · 可爱二次元v1.2版", -1, &f, RectF(0, 18, (REAL)rc.right, 54), &fmt, &dark);
    }

    SolidBrush panel(Color(205, 255, 255, 255));
    draw_rounded_rect(gr, RectF(16, 84, (REAL)rc.right - 32, 386), 28, Color(218, 255, 255, 255));
    // 移除白色填充区，使进度动画能够直接显示在 progress_bg 背景图上

    // 在主窗口绘制进度条（替代 owner-draw 子控件） - 纯图形化，无数字
    const int pad = 24;
    const int progX = pad;
    const int progY = 470;
    const int progW = rc.right - pad * 2;
    const int progH = 54;
    RectF full((REAL)progX, (REAL)progY, (REAL)progW, (REAL)progH);

    // 背景图固定尺寸 1070x100，并在进度条区域内垂直居中、水平居中显示
    const REAL bgW = 1070.0f;
    const REAL bgH = 85.0f;
    const REAL bgX = ((REAL)rc.right - bgW) / 2.0f;
    const REAL bgY = (REAL)progY + ((REAL)progH - bgH) / 2.0f;
    // 绘制背景图片（如果有）
    if (g_progress_bg) {
        gr.DrawImage(g_progress_bg, RectF(bgX, bgY, bgW, bgH));
    } else {
    }


        // 进度动画：使用4张图片循环平铺，并根据进度向右偏移；到达100%时替换为第5张图片位于右侧
        const REAL padding = 6.0f;
        // 将动画区域绑定到 progress_bg 的内部区域，而非填充区域，保证动画在背景图内显示
        RectF animArea((REAL)bgX + padding, (REAL)bgY + padding, (REAL)bgW - padding * 2, (REAL)bgH - padding * 2);
        if (animArea.Width > 8 && animArea.Height > 8) {
            if (g.progressValue >= 100 && g_progress_done && g_progress_done->GetLastStatus() == Ok) {
                // 完成：固定尺寸 100x100 绘制完成图片，放置在 animArea 右侧（允许超出但不裁剪）
                const REAL imgW = 100.0f;
                const REAL imgH = 100.0f;
                REAL x = animArea.GetRight() - imgW - 4.0f;
                REAL y = animArea.Y + (animArea.Height - imgH) / 2.0f;
                gr.DrawImage(g_progress_done, RectF(x, y, imgW, imgH));
            }
            else if (g_progress_anim1 && g_progress_anim2 && g_progress_anim3
                     && g_progress_anim1->GetLastStatus() == Ok && g_progress_anim2->GetLastStatus() == Ok
                     && g_progress_anim3->GetLastStatus() == Ok) {
                // 使用固定尺寸 100x100 像素进行显示（如 animArea 小于该尺寸将被裁剪）
                const double frameMs = 1000.0 / 5.0; // 每帧毫秒
                int frameIndex = 0;
                if (frameMs > 0.0) frameIndex = static_cast<int>(std::floor(g.anim_phase / frameMs)) % 4;
                Image* frameImg = (frameIndex == 0) ? g_progress_anim1 : (frameIndex == 1) ? g_progress_anim2 : (frameIndex == 2) ? g_progress_anim3 : g_progress_anim4;
                if (frameImg && frameImg->GetLastStatus() == Ok) {
                    // 固定尺寸 100x100 像素显示，不裁剪（可超出 animArea）
                    const REAL imgW = 100.0f;
                    const REAL imgH = 100.0f;
                    // 以进度决定 x：从 animArea.X 到 animArea.Right - imgW
                    const REAL ratioPos = (REAL)std::clamp((double)g.progressValue / 100.0, 0.0, 1.0);
                    const REAL available = animArea.Width - imgW;
                    REAL x = animArea.X + available * ratioPos;
                    REAL y = animArea.Y + (animArea.Height - imgH) / 2.0f;

                    // 绘制当前帧（不使用裁剪，完整显示）
                    gr.DrawImage(frameImg, RectF(x, y, imgW, imgH));
                }
            }
        }
    }

static void draw_labels(HWND hwnd, HDC hdc) {
    RECT rc{}; GetClientRect(hwnd, &rc);
    Graphics gr(hdc);
    gr.SetTextRenderingHint(TextRenderingHintAntiAlias);
    FontFamily fam(L"Microsoft YaHei UI");
    Font f(&fam, 14, FontStyleRegular, UnitPixel);
    Font fb(&fam, 15, FontStyleBold, UnitPixel);
    SolidBrush text(Color(255, 91, 76, 122));

    // 调整文字位置，避免与输入框重叠
    gr.DrawString(L"游戏目录：", -1, &fb, RectF(32, 254, 112, 24), nullptr, &text);
    gr.DrawString(L"输出目录：", -1, &fb, RectF(32, 296, 112, 24), nullptr, &text);
    gr.DrawString(L"拖放识别：", -1, &fb, RectF(32, 338, 112, 24), nullptr, &text);
    gr.DrawString(L"DAT范围：", -1, &fb, RectF(32, 384, 112, 24), nullptr, &text);

    SolidBrush hint(Color(255, 120, 103, 139));
    gr.DrawString(L"拖入 .CMF / DAT 目录 / 游戏根目录，会自动识别路径", -1, &f, RectF(170, 342, (REAL)rc.right - 190, 28), nullptr, &hint);
}

static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE:
        g.hwnd = hwnd;
        create_controls(hwnd);
        append_log(L"启动成功 · Win32 / ISO C++20 / x64 / MSVC v145");
        append_log(L"GUI 不使用控制台交互，所有操作均通过窗口、消息框、拖放与日志完成。");
        append_log(L"资源目录：" + (app_root() / L"assets").wstring());
        return 0;
    case WM_SIZE: {
        if (!g.editGame) break;
        RECT rc{}; GetClientRect(hwnd, &rc);
        const int w = rc.right - 48;
        MoveWindow(g.editGame, 150, 250, w - 246, 34, TRUE);
        MoveWindow(GetDlgItem(hwnd, IDC_BTN_GAME_PATH), w - 58, 250, 82, 34, TRUE);
        MoveWindow(g.editOutput, 150, 292, w - 246, 34, TRUE);
        MoveWindow(GetDlgItem(hwnd, IDC_BTN_OUTPUT), w - 58, 292, 82, 34, TRUE);
        MoveWindow(g.editDrop, 150, 334, w - 24, 34, TRUE);
        MoveWindow(g.labelStart, 24, 380, 110, 30, TRUE);
        MoveWindow(g.sliderStart, 145, 380, 280, 30, TRUE);
        MoveWindow(g.valueStart, 435, 380, 60, 30, TRUE);
        MoveWindow(g.labelEnd, 24, 418, 110, 30, TRUE);
        MoveWindow(g.sliderEnd, 145, 418, 280, 30, TRUE);
        MoveWindow(g.valueEnd, 435, 418, 60, 30, TRUE);
        MoveWindow(g.status, 24, 540, w, 24, TRUE);
        MoveWindow(g.log, 24, 570, w, std::max<int>(120, rc.bottom - 594), TRUE);
        return 0;
    }
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wp);
        HWND hCtrl = (HWND)lp;
        // 对 DAT 范围标签保持白色背景
        if (hCtrl == g.labelStart || hCtrl == g.labelEnd) {
            SetBkMode(dc, OPAQUE);
            SetBkColor(dc, RGB(255, 255, 255));
            SetTextColor(dc, RGB(105, 79, 124));
            return (LRESULT)(g_bg_brush ? g_bg_brush : GetStockObject(WHITE_BRUSH));
        }
        // 其他静态控件使用不透明面板背景，避免与 GDI+ 自绘混合产生重影
        SetBkMode(dc, OPAQUE);
        SetBkColor(dc, RGB(255, 255, 255));
        SetTextColor(dc, RGBX(105, 79, 124));
        return (LRESULT)(g_bg_brush ? g_bg_brush : GetStockObject(WHITE_BRUSH));
    }
    case WM_CTLCOLOREDIT: {
        HDC dc = reinterpret_cast<HDC>(wp);
        SetBkColor(dc, RGB(255, 253, 255));
        SetTextColor(dc, RGB(83, 66, 95));
        return (LRESULT)GetStockObject(WHITE_BRUSH);
    }
    case WM_COMMAND:
        if (HIWORD(wp) == BN_CLICKED) {
            switch (LOWORD(wp)) {
            case IDC_BTN_GAME_PATH: {
                fs::path p;
                if (browse_folder(hwnd, p, L"选择游戏客户端目录")) { 
                    g.config.game_path = p; 
                    set_edit(g.editGame, p.wstring()); 
                    save_config(g.config); 
                    update_dat_range_sliders();
                }
                return 0;
            }
            case IDC_BTN_OUTPUT: {
                fs::path p;
                if (browse_folder(hwnd, p, L"选择输出目录")) { g.config.output_dir = p; set_edit(g.editOutput, p.wstring()); save_config(g.config); }
                return 0;
            }
            case IDC_BTN_UNPACK_CMF:
                if (!g.busy) start_operation(run_unpack_cmf_folder);
                return 0;
            case IDC_BTN_UNPACK_DAT:
                if (!g.busy) start_operation(run_unpack_dat);
                return 0;
            case IDC_BTN_REPACK:
                if (!g.busy) start_operation(run_repack);
                return 0;
            }
        }
        break;
    case WM_HSCROLL: {
        // 处理滑块拖动
        HWND hSlider = (HWND)lp;
        if (hSlider == g.sliderStart || hSlider == g.sliderEnd) {
            int pos = (int)SendMessageW(hSlider, TBM_GETPOS, 0, 0);
            wchar_t buf[64];

            if (hSlider == g.sliderStart) {
                // 更新起始值显示
                StringCchPrintfW(buf, _countof(buf), L"%d", pos);
                SetWindowTextW(g.valueStart, buf);
                StringCchPrintfW(buf, _countof(buf), L"起始: %d", pos);
                SetWindowTextW(g.labelStart, buf);

                // 确保起始值不大于结束值
                int endPos = (int)SendMessageW(g.sliderEnd, TBM_GETPOS, 0, 0);
                if (pos > endPos) {
                    SendMessageW(g.sliderEnd, TBM_SETPOS, TRUE, pos);
                    StringCchPrintfW(buf, _countof(buf), L"%d", pos);
                    SetWindowTextW(g.valueEnd, buf);
                    StringCchPrintfW(buf, _countof(buf), L"结束: %d", pos);
                    SetWindowTextW(g.labelEnd, buf);
                }
            } else if (hSlider == g.sliderEnd) {
                // 更新结束值显示
                StringCchPrintfW(buf, _countof(buf), L"%d", pos);
                SetWindowTextW(g.valueEnd, buf);
                StringCchPrintfW(buf, _countof(buf), L"结束: %d", pos);
                SetWindowTextW(g.labelEnd, buf);

                // 确保结束值不小于起始值
                int startPos = (int)SendMessageW(g.sliderStart, TBM_GETPOS, 0, 0);
                if (pos < startPos) {
                    SendMessageW(g.sliderStart, TBM_SETPOS, TRUE, pos);
                    StringCchPrintfW(buf, _countof(buf), L"%d", pos);
                    SetWindowTextW(g.valueStart, buf);
                    StringCchPrintfW(buf, _countof(buf), L"起始: %d", pos);
                    SetWindowTextW(g.labelStart, buf);
                }
            }
        }
        return 0;
    }
    case WM_NOTIFY: {
        // 不再需要处理 UPDOWN 控件，保留以备将来使用
        return 0;
    }
    case WM_DROPFILES: {
        HDROP drop = reinterpret_cast<HDROP>(wp);
        const UINT count = DragQueryFileW(drop, 0xFFFFFFFF, nullptr, 0);
        std::vector<std::wstring> paths;
        paths.reserve(count);
        std::vector<wchar_t> buf;
        buf.resize(32768);
        for (UINT i = 0; i < count; ++i) {
            if (DragQueryFileW(drop, i, buf.data(), (UINT)buf.size())) paths.emplace_back(buf.data());
        }
        DragFinish(drop);
        identify_drop(paths);
        return 0;
    }
    case WM_APP_LOG: {
        // 批量取出队列中的日志并一次性追加，减少 UI 刷新次数
        std::deque<std::wstring*> items;
        {
            std::lock_guard<std::mutex> lk(g_log_mutex);
            items.swap(g_log_queue);
        }
        for (auto* s : items) {
            if (s) { append_log(*s); delete s; }
        }
        return 0;
    }
    case WM_APP_PROGRESS: {
        int value = 0;
        std::wstring text;
        {
            std::lock_guard<std::mutex> lk(g_progress_mutex);
            value = g_pending_progress_value;
            text = g_pending_progress_text;
            // 允许后续更新再次 PostMessage
            g_progress_posted.store(false);
        }
        g.progressValue = value;
        // 节流策略：只在进度变化>=2%或到达100%时才重绘，避免过度UI更新拖慢解压
        bool shouldUpdate = (g.progressValue == 100) ||
                            (g.progressValue == 0) ||
                            (abs(g.progressValue - g.lastDrawnProgress) >= 1);
        if (shouldUpdate) {
            g.lastDrawnProgress = g.progressValue;
            RECT client{}; GetClientRect(hwnd, &client);
            // 计算进度背景区域（与 draw_main_background 中的常量对应）
            const int progY_local = 470;
            const int progH_local = 54;
            const int bgH_local = 85; // progress_bg 高度
            int top = progY_local + (progH_local - bgH_local) / 2; // bgY
            RECT pr{24, top, client.right - 24, top + bgH_local};
            InvalidateRect(hwnd, &pr, FALSE);
            // 使用异步更新，不调用UpdateWindow，让消息队列自然处理
        }
        // 状态栏仅显示文字描述，不显示数字
        set_status(text);
        return 0;
    }
    case WM_APP_OPERATION_DONE:
        set_busy(false);
        gui_progress(100, L"操作完成");
        // 操作完成时强制刷新一次，确保进度条显示为100%
        {
            RECT client{}; GetClientRect(hwnd, &client);
            const int progY_local2 = 470;
            const int progH_local2 = 54;
            const int bgH_local2 = 85;
            int top2 = progY_local2 + (progH_local2 - bgH_local2) / 2;
            RECT pr{24, top2, client.right - 24, top2 + bgH_local2};
            InvalidateRect(hwnd, &pr, FALSE);
            UpdateWindow(hwnd);
        }
        // 清理消息队列中尚未处理的日志/进度消息，避免在操作已完成后继续处理陈旧回调
        {
            MSG msg{};
            // 删除所有待处理的 WM_APP_PROGRESS 消息并释放其分配的内存
            while (PeekMessageW(&msg, hwnd, WM_APP_PROGRESS, WM_APP_PROGRESS, PM_REMOVE)) {
                auto* p = reinterpret_cast<ProgressPacket*>(msg.lParam);
                if (p) delete p;
            }
            // 删除消息队列中的 WM_APP_LOG 消息（这些消息的 lParam 为 0），并清理日志队列中尚未被处理的字符串
            while (PeekMessageW(&msg, hwnd, WM_APP_LOG, WM_APP_LOG, PM_REMOVE)) { /* just remove message */ }
            {
                std::deque<std::wstring*> items;
                {
                    std::lock_guard<std::mutex> lk(g_log_mutex);
                    items.swap(g_log_queue);
                }
                for (auto* s : items) if (s) delete s;
            }
            // 清理合并的进度状态，避免在操作完成后展示陈旧进度
            {
                std::lock_guard<std::mutex> lk(g_progress_mutex);
                g_pending_progress_value = 100;
                g_pending_progress_text.clear();
                g_progress_posted.store(false);
            }
        }
        return 0;
    case WM_APP_OPERATION_ERROR:
        set_busy(false);
        return 0;
    case WM_TIMER: {
        const UINT_PTR TIMER_ID = 0xC0DE;
        if ((UINT_PTR)wp == TIMER_ID) {
            // 更新动画相位并刷新进度条区域，减少重绘范围
            uint64_t now = GetTickCount64();
            uint64_t last = g.anim_last_tick;
            if (last == 0) last = now;
            uint64_t delta = (now > last) ? (now - last) : 0;
            g.anim_last_tick = now;
            // anim_phase 以毫秒计数，用于时间驱动的帧切换
            g.anim_phase += (double)delta;
            // 限制 anim_phase 防止无限增大
            if (g.anim_phase > 1e8) g.anim_phase = fmod(g.anim_phase, 1e6);
            RECT client{}; GetClientRect(hwnd, &client);
            const int progY_local3 = 470;
            const int progH_local3 = 54;
            const int bgH_local3 = 85;
            int top3 = progY_local3 + (progH_local3 - bgH_local3) / 2;
            RECT pr{24, top3, client.right - 24, top3 + bgH_local3};
            InvalidateRect(hwnd, &pr, FALSE);
        }
        return 0;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps{};
        HDC dc = BeginPaint(hwnd, &ps);

        // 使用双缓冲技术避免闪烁
        RECT rc{}; GetClientRect(hwnd, &rc);
        HDC memDC = CreateCompatibleDC(dc);
        HBITMAP memBitmap = CreateCompatibleBitmap(dc, rc.right, rc.bottom);
        HBITMAP oldBitmap = (HBITMAP)SelectObject(memDC, memBitmap);

        // 在内存DC上绘制
        draw_main_background(hwnd, memDC);
        draw_labels(hwnd, memDC);

        // 一次性复制到屏幕DC
        BitBlt(dc, 0, 0, rc.right, rc.bottom, memDC, 0, 0, SRCCOPY);

        // 清理
        SelectObject(memDC, oldBitmap);
        DeleteObject(memBitmap);
        DeleteDC(memDC);

        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_CLOSE:
        if (g.busy) {
            MessageBoxW(hwnd, L"当前仍有操作正在进行。请等待操作完成后再关闭程序。", L"提示", MB_ICONINFORMATION);
            return 0;
        }
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static void init_gdi() {
    GdiplusStartupInput input;
    GdiplusStartup(&g_gdiplus_token, &input, nullptr);
}

static void shutdown_gdi() {
    delete g_logo; delete g_btn_cmf; delete g_btn_dat; delete g_btn_repack; delete g_progress_bg; delete g_progress_fill;
    delete g_progress_anim1; delete g_progress_anim2; delete g_progress_anim3; delete g_progress_anim4; delete g_progress_done;
    g_logo = g_btn_cmf = g_btn_dat = g_btn_repack = g_progress_bg = g_progress_fill = nullptr;
    g_progress_anim1 = g_progress_anim2 = g_progress_anim3 = g_progress_anim4 = g_progress_done = nullptr;
    if (g_bg_brush) { DeleteObject(g_bg_brush); g_bg_brush = nullptr; }
    if (g_gdiplus_token) { GdiplusShutdown(g_gdiplus_token); g_gdiplus_token = 0; }
}

static void load_assets() {
    g_logo = load_image_asset(L"logo.png");
    g_btn_cmf = load_image_asset(L"btn_unpack_cmf.png");
    g_btn_dat = load_image_asset(L"btn_unpack_dat.png");
    g_btn_repack = load_image_asset(L"btn_repack.png");
    g_progress_bg = load_image_asset(L"progress_bg.png");
    g_progress_anim1 = load_image_asset(L"progress_anim1.png");
    g_progress_anim2 = load_image_asset(L"progress_anim2.png");
    g_progress_anim3 = load_image_asset(L"progress_anim3.png");
    g_progress_anim4 = load_image_asset(L"progress_anim4.png");
    g_progress_done = load_image_asset(L"progress_done.png");
}

int WINAPI wWinMain(
    _In_ HINSTANCE hInst,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ PWSTR lpCmdLine,
    _In_ int nCmdShow)
{
    (void)hPrevInstance;  // 未使用的参数
    (void)lpCmdLine;      // 未使用的参数

    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&icc);

    // 初始化 COM，检查返回值
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        MessageBoxW(nullptr, L"COM 初始化失败", L"错误", MB_ICONERROR);
        return 1;
    }

    init_gdi();
    load_assets();

    g.config = load_config();
    g_font = CreateFontW(-16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
    g_font_bold = CreateFontW(-17, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
    // 为静态控件创建不透明背景画刷（与窗口内部面板背景近似）
    g_bg_brush = CreateSolidBrush(RGB(255, 255, 255));

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.hInstance = hInst;
    wc.lpfnWndProc = MainWndProc;
    wc.lpszClassName = L"ClosersCMFToolsGUIv1.2";
    wc.hIcon = static_cast<HICON>(LoadImageW(hInst, MAKEINTRESOURCEW(IDI_ICON1), IMAGE_ICON,
        32, 32, LR_DEFAULTSIZE));
    wc.hIconSm = static_cast<HICON>(LoadImageW(hInst, MAKEINTRESOURCEW(IDI_ICON1), IMAGE_ICON,
        16, 16, LR_DEFAULTSIZE));
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(WHITE_BRUSH));
    wc.style = CS_HREDRAW | CS_VREDRAW;
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(WS_EX_APPWINDOW | WS_EX_ACCEPTFILES, wc.lpszClassName,
        L"Closers CMF TOOLS · 二次元可爱 GUI v1.2", (WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME) | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        CW_USEDEFAULT, CW_USEDEFAULT, 1120, 780, nullptr, nullptr, hInst, nullptr);
    if (!hwnd) {
        shutdown_gdi();
        if (g_font) DeleteObject(g_font);
        if (g_font_bold) DeleteObject(g_font_bold);
        CoUninitialize();
        return 1;
    }

    SendMessageW(hwnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(wc.hIcon));
    SendMessageW(hwnd, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(wc.hIconSm));

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    if (g_font) DeleteObject(g_font);
    if (g_font_bold) DeleteObject(g_font_bold);
    shutdown_gdi();
    CoUninitialize();
    return (int)msg.wParam;
}
