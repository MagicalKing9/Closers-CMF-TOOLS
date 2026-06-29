/**
 * Closers CMF TOOLS 解包/封包工具 v1.0版
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <algorithm>
#include <filesystem>
#include <regex>
#include <cstdint>
#include <cstring>
#include <zlib.h>

namespace fs = std::filesystem;

// -------------------- 常量定义 --------------------
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

// -------------------- 工具函数 --------------------
uint32_t read_u32_le(const uint8_t* p) {
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

void write_u32_le(uint8_t* p, uint32_t v) {
    p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF;
    p[2] = (v >> 16) & 0xFF; p[3] = (v >> 24) & 0xFF;
}

std::string utf16le_to_utf8(const uint8_t* data, size_t len) {
    std::string u8;
    for (size_t i = 0; i + 1 < len; i += 2) {
        uint32_t cp = data[i] | (data[i + 1] << 8);
        if (cp == 0) break;
        if (cp < 0x80) { u8 += (char)cp; }
        else if (cp < 0x800) {
            u8 += (char)(0xC0 | (cp >> 6)); u8 += (char)(0x80 | (cp & 0x3F));
        }
        else {
            u8 += (char)(0xE0 | (cp >> 12)); u8 += (char)(0x80 | ((cp >> 6) & 0x3F)); u8 += (char)(0x80 | (cp & 0x3F));
        }
    }
    return u8;
}

std::vector<uint8_t> utf8_to_utf16le(const std::string& s) {
    std::vector<uint8_t> out;
    size_t i = 0;
    while (i < s.length()) {
        uint8_t c = s[i++];
        uint32_t cp = 0;
        if (c < 0x80) cp = c;
        else if ((c >> 5) == 0x06) { cp = ((c & 0x1F) << 6) | (s[i++] & 0x3F); }
        else if ((c >> 4) == 0x0E) { cp = ((c & 0x0F) << 12) | ((s[i++] & 0x3F) << 6); cp |= (s[i++] & 0x3F); }
        out.push_back(cp & 0xFF);
        out.push_back((cp >> 8) & 0xFF);
    }
    return out;
}

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

// -------------------- 加解密 --------------------
uint32_t _swap(uint32_t x) {
    return ((x << 24) | (x >> 24) | (x & 0x00FFFF00));
}

std::vector<uint8_t> decrypt_table_memoryfile2(const std::vector<uint8_t>& data, uint32_t key1, uint32_t key2, uint32_t key3) {
    std::vector<uint8_t> res = data;
    while (res.size() % 4 != 0) res.push_back(0);
    size_t n = res.size() / 4;
    uint32_t* arr = (uint32_t*)res.data();
    size_t i = 0;
    while (i + 2 < n) {
        arr[i] = _swap(arr[i]) ^ key1;
        arr[i + 1] = _swap(arr[i + 1]) ^ key2;
        arr[i + 2] = _swap(arr[i + 2]) ^ key3;
        i += 3;
    }
    while (i < n) {
        arr[i] = _swap(arr[i]) ^ key1;
        i += 1;
    }
    return res;
}

std::vector<uint8_t> encrypt_table_memoryfile2(const std::vector<uint8_t>& data, uint32_t key1, uint32_t key2, uint32_t key3) {
    std::vector<uint8_t> res = data;
    while (res.size() % 4 != 0) res.push_back(0);
    size_t n = res.size() / 4;
    uint32_t* arr = (uint32_t*)res.data();
    size_t i = 0;
    while (i + 2 < n) {
        arr[i] = _swap(arr[i] ^ key1);
        arr[i + 1] = _swap(arr[i + 1] ^ key2);
        arr[i + 2] = _swap(arr[i + 2] ^ key3);
        i += 3;
    }
    while (i < n) {
        arr[i] = _swap(arr[i] ^ key1);
        i += 1;
    }
    return res;
}

std::vector<uint8_t> decrypt_cmf_table(const std::vector<uint8_t>& table_data, int version) {
    const uint32_t* keys = (version <= 3) ? OLD_KEYS : NEW_KEYS;
    return decrypt_table_memoryfile2(table_data, keys[0], keys[1], keys[2]);
}

std::vector<uint8_t> encrypt_cmf_table(const std::vector<uint8_t>& table_data, int version) {
    const uint32_t* keys = (version <= 3) ? OLD_KEYS : NEW_KEYS;
    return encrypt_table_memoryfile2(table_data, keys[0], keys[1], keys[2]);
}

int detect_version(const std::vector<uint8_t>& header) {
    if (header.size() < 36) throw std::runtime_error("文件太小");
    uint16_t ver_short = header[34] | (header[35] << 8);
    for (const auto& kv : VERSION_MARK) {
        if (kv.second == ver_short) return kv.first;
    }
    throw std::runtime_error("未知CMF版本标记");
}

uint32_t decrypt_file_count(uint32_t enc_count) {
    uint32_t swap_val = ((enc_count << 24) & 0xFF000000) |
        ((enc_count >> 0) & 0x0000FF00) |
        ((enc_count << 0) & 0x00FF0000) |
        ((enc_count >> 24) & 0x000000FF);
    return swap_val ^ FILE_COUNT_KEY;
}

uint32_t encrypt_file_count(uint32_t count) {
    uint32_t xored = count ^ FILE_COUNT_KEY;
    return ((xored << 24) & 0xFF000000) |
        ((xored >> 0) & 0x0000FF00) |
        ((xored << 0) & 0x00FF0000) |
        ((xored >> 24) & 0x000000FF);
}

// -------------------- CMF 条目解析 --------------------
struct CmfEntry {
    std::string name;
    uint32_t size = 0;
    uint32_t zsize = 0;
    uint32_t offset = 0;
    uint32_t flag = 0;
    std::vector<uint8_t> raw_data;
};

std::vector<CmfEntry> parse_entries(const std::vector<uint8_t>& decrypted) {
    std::vector<CmfEntry> entries;
    for (size_t i = 0; i + ENTRY_SIZE <= decrypted.size(); i += ENTRY_SIZE) {
        const uint8_t* entry_buf = decrypted.data() + i;
        size_t null_pos = 512;
        for (size_t j = 0; j < 512; j += 2) {
            if (entry_buf[j] == 0 && entry_buf[j + 1] == 0) {
                null_pos = j; break;
            }
        }
        std::string name = utf16le_to_utf8(entry_buf, null_pos);
        if (name.empty()) continue;

        CmfEntry ent;
        ent.name = name;
        ent.size = read_u32_le(entry_buf + 512);
        ent.zsize = read_u32_le(entry_buf + 516);
        ent.offset = read_u32_le(entry_buf + 520);
        ent.flag = read_u32_le(entry_buf + 524);
        entries.push_back(ent);
    }
    return entries;
}

std::vector<uint8_t> build_entries(const std::vector<CmfEntry>& entries) {
    std::vector<uint8_t> table;
    for (const auto& ent : entries) {
        std::vector<uint8_t> name_bytes = utf8_to_utf16le(ent.name);
        if (name_bytes.size() > 512) throw std::runtime_error("文件名过长: " + ent.name);

        std::vector<uint8_t> entry_buf(ENTRY_SIZE, 0);
        std::memcpy(entry_buf.data(), name_bytes.data(), name_bytes.size());

        write_u32_le(entry_buf.data() + 512, ent.size);
        write_u32_le(entry_buf.data() + 516, ent.zsize);
        write_u32_le(entry_buf.data() + 520, ent.offset);
        write_u32_le(entry_buf.data() + 524, ent.flag);

        table.insert(table.end(), entry_buf.begin(), entry_buf.end());
    }
    return table;
}

std::string safe_filename(std::string name) {
    if (name.empty()) return "";
    size_t null_idx = name.find('\0');
    if (null_idx != std::string::npos) name = name.substr(0, null_idx);

    std::string allowed = "/\\._- ";
    std::string cleaned;
    for (char c : name) {
        if ((unsigned char)c >= 32 || allowed.find(c) != std::string::npos) {
            cleaned += c;
        }
    }
    return cleaned;
}

// -------------------- Zlib 压缩/解压 --------------------
std::vector<uint8_t> decompress_data(const uint8_t* data, size_t zsize, size_t size) {
    std::vector<uint8_t> out(size);
    uLongf destLen = static_cast<uLongf>(size);
    if (uncompress(out.data(), &destLen, data, zsize) == Z_OK) {
        out.resize(destLen);
        return out;
    }
    // 解压失败返回原数据
    return std::vector<uint8_t>(data, data + zsize);
}

std::vector<uint8_t> compress_data(const std::vector<uint8_t>& in) {
    uLongf destLen = compressBound(static_cast<uLongf>(in.size()));
    std::vector<uint8_t> out(destLen);
    if (compress(out.data(), &destLen, in.data(), in.size()) == Z_OK) {
        out.resize(destLen);
        return out;
    }
    return in;
}

// -------------------- 解包单个CMF --------------------
int unpack_single_cmf(const fs::path& cmf_path, const fs::path& output_dir, const std::set<std::string>& allowed_exts) {
    std::ifstream f(cmf_path, std::ios::binary);
    if (!f) return 0;
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    f.close();

    int version;
    try { version = detect_version(data); }
    catch (const std::exception& e) {
        std::cout << "  " << cmf_path.filename().string() << ": 版本检测失败 - " << e.what() << "\n";
        return 0;
    }

    uint32_t raw_count = read_u32_le(data.data() + 0x64);
    uint32_t file_count = decrypt_file_count(raw_count);
    if (file_count == 0 || file_count > 50000) {
        std::cout << "  " << cmf_path.filename().string() << ": 文件数量异常 (" << file_count << ")，跳过\n";
        return 0;
    }

    uint32_t table_size = file_count * ENTRY_SIZE;
    uint32_t data_start = HEADER_SIZE + table_size;
    uint32_t version_offset = (version >= 3) ? version : 0;

    if (data.size() < data_start + version_offset) {
        std::cout << "  " << cmf_path.filename().string() << ": 文件太小，跳过\n";
        return 0;
    }

    std::vector<uint8_t> table_data(data.begin() + TABLE_OFFSET, data.begin() + TABLE_OFFSET + table_size);
    std::vector<uint8_t> dec_table = decrypt_cmf_table(table_data, version);
    std::vector<CmfEntry> entries = parse_entries(dec_table);

    int count = 0;
    for (const auto& ent : entries) {
        std::string name = safe_filename(ent.name);
        if (name.empty()) continue;

        fs::path p(name);
        std::string ext = to_lower(p.extension().string());
        if (!allowed_exts.empty() && allowed_exts.find(ext) == allowed_exts.end()) continue;

        uint32_t offset = ent.offset + data_start + version_offset;
        if (offset >= data.size()) continue;

        std::vector<uint8_t> raw;
        if (ent.flag == 0) {
            raw.assign(data.begin() + offset, data.begin() + offset + ent.size);
        }
        else if (ent.flag == 1) {
            if (data.size() > offset + 4 && memcmp(data.data() + offset, "\x89PNG", 4) == 0) {
                raw.assign(data.begin() + offset, data.begin() + offset + ent.size);
            }
            else {
                raw = decompress_data(data.data() + offset, ent.zsize, ent.size);
            }
        }
        else if (ent.flag == 2 || ent.flag == 3) {
            raw = decompress_data(data.data() + offset, ent.zsize, ent.size);
        }
        else {
            raw.assign(data.begin() + offset, data.begin() + offset + ent.zsize);
        }

        fs::path out_path = output_dir / name;
        fs::create_directories(out_path.parent_path());
        std::ofstream fout(out_path, std::ios::binary);
        if (fout) {
            fout.write((char*)raw.data(), raw.size());
            count++;
        }
    }
    return count;
}

// -------------------- 读取完整CMF数据 --------------------
struct ParsedCMF {
    int version;
    std::vector<uint8_t> original_header;
    std::vector<CmfEntry> entries;
    uint32_t version_offset;
    std::vector<uint8_t> padding;
};

ParsedCMF read_all_entries_with_data(const fs::path& cmf_path) {
    std::ifstream f(cmf_path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open file");
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    f.close();

    ParsedCMF cmf;
    cmf.version = detect_version(data);
    uint32_t raw_count = read_u32_le(data.data() + 0x64);
    uint32_t file_count = decrypt_file_count(raw_count);
    if (file_count == 0 || file_count > 50000) throw std::runtime_error("文件数量异常");

    uint32_t table_size = file_count * ENTRY_SIZE;
    uint32_t data_start = HEADER_SIZE + table_size;
    cmf.version_offset = (cmf.version >= 3) ? cmf.version : 0;

    if (cmf.version_offset > 0 && data.size() >= data_start + cmf.version_offset) {
        cmf.padding.assign(data.begin() + data_start, data.begin() + data_start + cmf.version_offset);
    }

    std::vector<uint8_t> table_data(data.begin() + TABLE_OFFSET, data.begin() + TABLE_OFFSET + table_size);
    std::vector<uint8_t> dec_table = decrypt_cmf_table(table_data, cmf.version);
    cmf.entries = parse_entries(dec_table);

    cmf.original_header.assign(data.begin(), data.begin() + HEADER_SIZE);

    for (auto& ent : cmf.entries) {
        uint32_t offset = data_start + ent.offset + cmf.version_offset;
        if (ent.flag == 0) {
            ent.raw_data.assign(data.begin() + offset, data.begin() + offset + ent.size);
        }
        else if (ent.flag == 1 || ent.flag == 2) {
            ent.raw_data = decompress_data(data.data() + offset, ent.zsize, ent.size);
        }
        else {
            ent.raw_data.assign(data.begin() + offset, data.begin() + offset + ent.size);
        }
    }
    return cmf;
}

// -------------------- 重建CMF --------------------
std::vector<uint8_t> rebuild_cmf(const ParsedCMF& cmf, const std::map<std::string, std::vector<uint8_t>>& replaced_map) {
    std::vector<uint8_t> data_section = cmf.padding;
    std::vector<CmfEntry> new_entries;

    for (const auto& ent : cmf.entries) {
        CmfEntry ne = ent;
        auto it = replaced_map.find(ent.name);
        std::vector<uint8_t> raw_data = (it != replaced_map.end()) ? it->second : ent.raw_data;

        std::vector<uint8_t> compressed;
        if (ne.flag == 0) {
            compressed = raw_data;
            ne.zsize = raw_data.size();
        }
        else {
            compressed = compress_data(raw_data);
            ne.zsize = compressed.size();
        }
        ne.size = raw_data.size();
        ne.raw_data = compressed; // 临时存储压缩后数据
        new_entries.push_back(ne);
    }

    uint32_t offset = 0;
    for (auto& ne : new_entries) {
        ne.offset = offset;
        data_section.insert(data_section.end(), ne.raw_data.begin(), ne.raw_data.end());
        offset += ne.zsize;
        ne.raw_data.clear();
    }

    std::vector<uint8_t> table_plain = build_entries(new_entries);
    std::vector<uint8_t> table_enc = encrypt_cmf_table(table_plain, cmf.version);

    std::vector<uint8_t> final_cmf = cmf.original_header;
    uint32_t raw_count_enc = encrypt_file_count(new_entries.size());
    write_u32_le(final_cmf.data() + 0x64, raw_count_enc);

    final_cmf.insert(final_cmf.end(), table_enc.begin(), table_enc.end());
    final_cmf.insert(final_cmf.end(), data_section.begin(), data_section.end());

    return final_cmf;
}

void repack_cmf_rebuild(const fs::path& cmf_path, const std::map<std::string, std::vector<uint8_t>>& pak_files) {
    fs::path bak_dir = fs::current_path() / "bak";
    fs::create_directories(bak_dir);

    ParsedCMF cmf;
    try { cmf = read_all_entries_with_data(cmf_path); }
    catch (std::exception& e) { std::cout << "  读取原始CMF失败: " << e.what() << "\n"; return; }

    std::map<std::string, std::string> name_lower_map;
    for (const auto& ent : cmf.entries) name_lower_map[to_lower(ent.name)] = ent.name;

    std::map<std::string, std::vector<uint8_t>> matched_pak;
    for (const auto& kv : pak_files) {
        std::string lower = to_lower(kv.first);
        if (name_lower_map.count(lower)) matched_pak[name_lower_map[lower]] = kv.second;
        else std::cout << "    警告：pak中的文件 '" << kv.first << "' 未在CMF中找到\n";
    }

    int replace_count = 0;
    for (const auto& ent : cmf.entries) {
        if (matched_pak.count(ent.name) && matched_pak[ent.name] != ent.raw_data) {
            replace_count++;
            std::cout << "  替换: " << ent.name << " (" << ent.raw_data.size() << " -> " << matched_pak[ent.name].size() << " bytes)\n";
        }
    }

    if (replace_count == 0) {
        std::cout << "  没有文件需要替换\n";
        return;
    }

    fs::path bak_path = bak_dir / cmf_path.filename();
    if (!fs::exists(bak_path)) {
        fs::copy_file(cmf_path, bak_path);
        std::cout << "  原始文件已备份到 " << bak_path.string() << "\n";
    }

    std::vector<uint8_t> new_cmf = rebuild_cmf(cmf, matched_pak);

    // 写入
    std::ofstream out(cmf_path, std::ios::binary);
    out.write((char*)new_cmf.data(), new_cmf.size());
    std::cout << "  封包完成，替换了 " << replace_count << " 个文件\n";
}

// -------------------- 配置与菜单 --------------------
struct Config {
    std::string game_path;
    std::string output_dir;
};

Config load_config() {
    Config cfg;
    cfg.output_dir = (fs::current_path() / "unpack").string();
    std::ifstream f("config.ini");
    if (f) {
        std::string line;
        while (std::getline(f, line)) {
            size_t pos = line.find('=');
            if (pos != std::string::npos) {
                std::string k = line.substr(0, pos), v = line.substr(pos + 1);
                if (k == "game_path") cfg.game_path = v;
                if (k == "output_dir") cfg.output_dir = v;
            }
        }
    }
    return cfg;
}

void save_config(const Config& cfg) {
    std::ofstream f("config.ini");
    f << "game_path=" << cfg.game_path << "\n";
    f << "output_dir=" << cfg.output_dir << "\n";
}

std::string prompt_game_path(Config& config) {
    std::cout << "当前游戏目录: " << (config.game_path.empty() ? "未设置" : config.game_path) << "\n";
    std::cout << "请输入游戏目录（回车保留）: ";
    std::string inp; std::getline(std::cin, inp);
    if (!inp.empty()) {
        fs::path p(inp);
        if (fs::is_directory(p)) {
            config.game_path = fs::absolute(p).string();
            save_config(config);
        }
        else { std::cout << "路径不存在\n"; }
    }
    return config.game_path;
}

std::set<std::string> prompt_file_types() {
    std::cout << "文件类型：0-全部 1-PNG 2-DDS 3-X 4-OGG\n";
    std::cout << "输入如 1|2|4 (0=全部): ";
    std::string inp; std::getline(std::cin, inp);
    if (inp == "0" || inp.empty() || to_lower(inp) == "all") return {};
    std::set<std::string> exts;
    if (inp.find('1') != std::string::npos) exts.insert(".png");
    if (inp.find('2') != std::string::npos) exts.insert(".dds");
    if (inp.find('3') != std::string::npos) exts.insert(".x");
    if (inp.find('4') != std::string::npos) exts.insert(".ogg");
    return exts;
}

void unpack_cmf_folder(Config& config) {
    fs::path cmf_dir = fs::current_path() / "cmf";
    fs::path unpack_dir = fs::current_path() / "unpack";
    fs::create_directories(unpack_dir);
    if (!fs::exists(cmf_dir)) {
        fs::create_directories(cmf_dir);
        std::cout << "已创建 cmf 文件夹，请放入 .cmf 文件\n"; return;
    }

    std::vector<fs::path> cmfs;
    for (const auto& entry : fs::directory_iterator(cmf_dir)) {
        if (to_lower(entry.path().extension().string()) == ".cmf") cmfs.push_back(entry.path());
    }
    if (cmfs.empty()) { std::cout << "没有 .cmf 文件\n"; return; }

    std::cout << "按cmf名分文件夹？(Y/n): ";
    std::string grp_inp; std::getline(std::cin, grp_inp);
    bool grp = (to_lower(grp_inp) != "n" && grp_inp != "0");
    auto exts = prompt_file_types();

    int total = 0;
    for (const auto& cmf : cmfs) {
        fs::path outdir = grp ? (unpack_dir / cmf.filename()) : unpack_dir;
        std::cout << "\n处理 " << cmf.filename().string() << " ...\n";
        int n = unpack_single_cmf(cmf, outdir, exts);
        total += n; std::cout << "  " << n << " 文件\n";
    }
    std::cout << "\n完成，共 " << total << " 文件\n";
}

void unpack_game_dat(Config& config) {
    std::string gp = prompt_game_path(config);
    if (gp.empty()) return;
    fs::path dat_dir = fs::path(gp) / "DAT";
    if (!fs::is_directory(dat_dir)) { std::cout << "找不到 DAT 文件夹\n"; return; }

    std::vector<std::string> folders;
    std::regex re("^DAT\\d+$");
    for (const auto& entry : fs::directory_iterator(dat_dir)) {
        std::string name = entry.path().filename().string();
        if (std::regex_match(name, re)) folders.push_back(name);
    }
    std::sort(folders.begin(), folders.end(), [](const std::string& a, const std::string& b) {
        return std::stoi(a.substr(3)) < std::stoi(b.substr(3));
        });

    if (folders.empty()) { std::cout << "DAT 文件夹为空\n"; return; }
    std::cout << "找到 " << folders.size() << " 个: " << folders.front() << " ~ " << folders.back() << "\n";
    std::cout << "输入范围如 0-260 或 5: ";
    std::string inp; std::getline(std::cin, inp);
    if (inp.empty()) return;

    std::vector<std::string> target_dats;
    size_t dash = inp.find('-');
    if (dash != std::string::npos) {
        int s = std::stoi(inp.substr(0, dash)), e = std::stoi(inp.substr(dash + 1));
        for (int i = s; i <= e; i++) {
            std::string d = "DAT" + std::to_string(i);
            if (std::find(folders.begin(), folders.end(), d) != folders.end()) target_dats.push_back(d);
        }
    }
    else {
        std::string d = "DAT" + inp;
        if (std::find(folders.begin(), folders.end(), d) != folders.end()) target_dats.push_back(d);
    }

    std::cout << "当前输出目录: " << config.output_dir << "\n输入新目录（回车保留）: ";
    std::string out_inp; std::getline(std::cin, out_inp);
    if (!out_inp.empty()) { config.output_dir = fs::absolute(out_inp).string(); save_config(config); }
    fs::path outdir(config.output_dir);
    fs::create_directories(outdir);
    auto exts = prompt_file_types();

    int total = 0;
    for (const auto& dat : target_dats) {
        fs::path dat_path = dat_dir / dat;
        std::vector<fs::path> cmfs;
        for (const auto& entry : fs::directory_iterator(dat_path)) {
            if (to_lower(entry.path().extension().string()) == ".cmf") cmfs.push_back(entry.path());
        }
        if (cmfs.empty()) continue;
        fs::path dat_out = outdir / dat;
        fs::create_directories(dat_out);
        std::cout << "\n处理 " << dat << " (" << cmfs.size() << " cmf)\n";
        for (const auto& cmf : cmfs) {
            fs::path out = dat_out / cmf.filename();
            int n = unpack_single_cmf(cmf, out, exts);
            total += n; std::cout << "  " << cmf.filename().string() << ": " << n << " 文件\n";
        }
    }
    std::cout << "\n完成，共 " << total << " 文件\n";
}

void process_repack(Config& config) {
    fs::path cmf_dir = fs::current_path() / "cmf";
    fs::path pak_dir = fs::current_path() / "pak";
    if (!fs::is_directory(cmf_dir) || !fs::is_directory(pak_dir)) {
        std::cout << "cmf 或 pak 文件夹不存在\n"; return;
    }
    std::vector<fs::path> cmfs;
    for (const auto& entry : fs::directory_iterator(cmf_dir)) {
        if (to_lower(entry.path().extension().string()) == ".cmf") cmfs.push_back(entry.path());
    }
    if (cmfs.empty()) { std::cout << "没有 .cmf 文件\n"; return; }

    std::map<std::string, std::vector<uint8_t>> pak_all;
    for (const auto& entry : fs::recursive_directory_iterator(pak_dir)) {
        if (entry.is_regular_file()) {
            std::string rel = fs::relative(entry.path(), pak_dir).string();
            std::replace(rel.begin(), rel.end(), '\\', '/');
            std::ifstream f(entry.path(), std::ios::binary);
            if (f) {
                pak_all[rel] = std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            }
        }
    }
    std::cout << "cmf 文件夹: " << cmfs.size() << " 个，pak 文件夹: " << pak_all.size() << " 个文件\n";
    if (pak_all.empty()) { std::cout << "没有文件需要封入\n"; return; }

    std::cout << "确认封包？(Y/n): ";
    std::string confirm; std::getline(std::cin, confirm);
    if (to_lower(confirm) == "n") return;

    for (const auto& cmf : cmfs) {
        std::cout << "\n处理 " << cmf.filename().string() << " ...\n";
        repack_cmf_rebuild(cmf, pak_all);
    }
}

int main() {
    Config config = load_config();
    std::cout << "========================================================\n";
    std::cout << "  Closers CMF TOOLS 解包/封包工具 v1.0(命令行版本)\n";
    std::cout << "  支持替换X/PNG/DDS/OGG\n";
    std::cout << "========================================================\n";

    while (true) {
        std::cout << "\n1. 解包 cmf 文件夹内的 cmf 文件\n";
        std::cout << "2. 解包游戏 DAT 文件夹内的cmf 文件\n";
        std::cout << "3. 封包（从 cmf 文件夹内读取原始包，从 pak 文件夹内读取替换文件）\n";
        std::cout << "4. 退出\n";
        std::cout << "选择: ";

        std::string choice;
        if (!std::getline(std::cin, choice)) break;

        if (choice == "1") unpack_cmf_folder(config);
        else if (choice == "2") unpack_game_dat(config);
        else if (choice == "3") process_repack(config);
        else if (choice == "4") break;
        else std::cout << "无效输入\n";
    }
    return 0;
}

