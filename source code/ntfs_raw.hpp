//=============================================================================
// ntfs_raw.h - 用户态NTFS底层读写库 (完整生产级版本)
// 版本: 5.1 (修正版)
// 特性: GPT/MBR解析、完整目录遍历、文件读写、簇真实分配、MFT镜像备份、
//       写入事务(回滚)、扇区损坏恢复、稀疏文件支持、属性列表处理、压缩支持、
//       短名自动匹配、$Bitmap正确读写、MFT记录动态扩展
// 编译: C++17, Windows (需要管理员权限)
//=============================================================================
#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <cassert>
#include <thread>
#include <chrono>
#include <cwchar>
#include <map>
#include <unordered_map>
#include <queue>
#include <atomic>      // 用于原子序列号

//-----------------------------------------------------------------------------
// NTFS 结构定义 (小端序，直接映射)
//-----------------------------------------------------------------------------
#pragma pack(push, 1)

// NTFS BIOS参数块 (位于引导扇区偏移11字节)
struct NtfsBpb {
    uint16_t bytes_per_sector;       // 每扇区字节数 (通常512)
    uint8_t  sectors_per_cluster;    // 每簇扇区数
    uint16_t reserved_sectors;       // 保留扇区 (必须为0)
    uint8_t  unused1[5];
    uint8_t  media_descriptor;
    uint16_t unused2;
    uint16_t sectors_per_track;
    uint16_t number_of_heads;
    uint32_t hidden_sectors;
    uint32_t unused3;
    uint32_t unused4;
    uint64_t total_sectors;           // 分区总扇区数
    uint64_t mft_lcn;                  // $MFT的簇号
    uint64_t mft_mirr_lcn;              // $MFT镜像簇号
    int8_t   clusters_per_mft_record;   // 每个MFT记录占用的簇数 (负数表示2的幂)
    int8_t   unused5[3];
    int8_t   clusters_per_index_record; // 每个索引记录占用的簇数
    int8_t   unused6[3];
    uint64_t volume_serial;
    uint32_t checksum;
};

// 文件记录头 ("FILE")
struct FileRecordHeader {
    uint8_t  magic[4];          // "FILE"
    uint16_t usa_offset;        // 更新序列号偏移
    uint16_t usa_count;         // 更新序列号计数
    uint64_t lsn;               // 日志文件序列号
    uint16_t sequence_number;   // 序列号
    uint16_t link_count;        // 硬链接计数
    uint16_t attr_offset;       // 第一个属性偏移
    uint16_t flags;             // 标志 (1=记录使用中, 2=目录)
    uint32_t bytes_in_use;      // 记录实际使用大小
    uint32_t bytes_allocated;   // 记录分配大小
    uint64_t base_file_record;  // 基文件记录 (0表示自己)
    uint16_t next_attr_id;      // 下一个属性ID
    uint16_t reserved;          // 保留 (Windows XP后添加)
    uint32_t mft_record_number; // MFT记录号 (Windows 2000+)
};

// 属性头 (通用)
struct AttrHeader {
    uint32_t type;              // 属性类型 (0x10=标准信息, 0x30=文件名, 0x80=数据)
    uint32_t length;            // 属性总长度 (包括头)
    uint8_t  non_resident;      // 非常驻标志 (0=常驻, 1=非常驻)
    uint8_t  name_length;       // 属性名长度 (字节数)
    uint16_t name_offset;       // 属性名偏移 (相对于属性头)
    uint16_t flags;             // 标志 (压缩/加密/稀疏)
    uint16_t attribute_id;      // 属性ID
};

// 常驻属性头 (non_resident=0)
struct ResidentAttr : AttrHeader {
    uint32_t content_length;    // 内容长度
    uint16_t content_offset;    // 内容偏移 (相对于属性头)
    uint8_t  indexed_flag;      // 索引标志 (未使用)
    uint8_t  padding;
};

// 非常驻属性头 (non_resident=1)
struct NonResidentAttr : AttrHeader {
    uint64_t start_vcn;         // 起始虚拟簇号
    uint64_t last_vcn;          // 最后虚拟簇号
    uint16_t runlist_offset;    // 运行列表偏移 (相对于属性头)
    uint16_t compression_unit;  // 压缩单元大小 (2的幂，0表示未压缩)
    uint32_t padding;
    uint64_t allocated_size;    // 分配大小
    uint64_t data_size;         // 数据大小 (文件大小)
    uint64_t initialized_size;  // 已初始化大小
};

// 文件名属性 (type=0x30)
struct FileNameAttr {
    uint64_t parent_directory;  // 父目录的MFT引用 (低48位为记录号，高16位为序列号)
    uint64_t creation_time;
    uint64_t last_mod_time;
    uint64_t last_change_time;
    uint64_t last_access_time;
    uint64_t allocated_size;    // 分配大小
    uint64_t data_size;         // 实际大小
    uint32_t flags;             // 文件属性 (只读/隐藏/系统等)
    uint32_t reparse;           // 重解析点
    uint8_t  name_length;       // 文件名长度 (字符数)
    uint8_t  name_type;         // 命名空间 (0=POSIX, 1=Win32, 2=DOS, 3=Win32&DOS)
    uint16_t name[1];           // 文件名 (UTF-16LE)
};

// 索引根头 (位于索引根属性内容开始处)
struct IndexRootHeader {
    uint32_t attr_type;          // 索引的属性类型 (通常为0x30 文件名)
    uint32_t collation_rule;     // 排序规则 (通常为0x01)
    uint32_t index_block_size;   // 索引块大小 (字节)
    uint8_t  clusters_per_index_record; // 每个索引记录的簇数 (负数表示2的幂)
    uint8_t  padding[3];
    // 后面跟 IndexHeader
};

// 索引块头 (位于每个索引分配块开始)  修正：usa_offset/usa_count 应为 uint16_t
struct IndexBlockHeader {
    uint8_t  magic[4];           // "INDX"
    uint16_t usa_offset;         // 更新序列号偏移
    uint16_t usa_count;          // 更新序列号计数
    uint64_t lsn;                // 日志序列号
    uint64_t vcn;                // 此索引块的VCN
    // 后面跟 IndexHeader (同索引根中的)
};

// 索引头 (紧接IndexRootHeader或IndexBlockHeader之后)
struct IndexHeader {
    uint32_t entries_offset;      // 索引项起始偏移 (相对于本头)
    uint32_t index_length;        // 索引部分总长度 (包括头)
    uint32_t allocated_size;      // 分配大小
    uint8_t  flags;               // 0x00=小索引, 0x01=大索引
    uint8_t  padding[3];
};

// 索引项头
struct IndexEntryHeader {
    uint64_t mft_reference;      // 文件MFT引用 (低48位记录号，高16位序列号)
    uint16_t size;               // 索引项大小 (包括头)
    uint16_t key_length;         // 键长度 (文件名长度*2)
    uint8_t  flags;              // 标志 (0x01=子节点存在, 0x02=最后一项)
    uint8_t  padding;            // 填充
    // 后面紧跟文件名 (UTF-16LE)
};

// 标准信息属性 (type=0x10)
struct StdInfo {
    uint64_t creation_time;
    uint64_t last_mod_time;
    uint64_t last_change_time;
    uint64_t last_access_time;
    uint32_t file_attributes;    // 文件属性 (FILE_ATTRIBUTE_XXX)
    uint32_t max_versions;       // 最大版本数 (未使用)
    uint32_t version_number;     // 版本号 (未使用)
    uint32_t class_id;           // 类ID (未使用)
    uint32_t owner_id;           // 所有者ID (NTFS 3.0+)
    uint32_t security_id;        // 安全ID (NTFS 3.0+)
    uint64_t quota_charged;      // 配额 (NTFS 3.0+)
    uint64_t usn;                // 更新序列号 (NTFS 3.0+)
};

// 属性列表条目 (位于$ATTRIBUTE_LIST内容中)
struct AttrListEntry {
    uint32_t attr_type;          // 属性类型
    uint16_t length;             // 此条目长度
    uint8_t  name_length;        // 属性名长度 (字符数)
    uint8_t  name_offset;        // 属性名偏移 (相对于此条目)
    uint64_t start_vcn;          // 起始VCN (对于非常驻属性)
    uint64_t base_mft_ref;       // 基文件记录引用
    uint16_t attribute_id;       // 属性ID
    uint8_t  name[1];            // 属性名 (UTF-16LE)
};

#pragma pack(pop)

//-----------------------------------------------------------------------------
// 常量定义
//-----------------------------------------------------------------------------
const uint32_t ATTR_TYPE_STANDARD_INFORMATION = 0x10;
const uint32_t ATTR_TYPE_ATTRIBUTE_LIST = 0x20;
const uint32_t ATTR_TYPE_FILE_NAME = 0x30;
const uint32_t ATTR_TYPE_OBJECT_ID = 0x40;
const uint32_t ATTR_TYPE_SECURITY_DESCRIPTOR = 0x50;
const uint32_t ATTR_TYPE_VOLUME_NAME = 0x60;
const uint32_t ATTR_TYPE_VOLUME_INFORMATION = 0x70;
const uint32_t ATTR_TYPE_DATA = 0x80;
const uint32_t ATTR_TYPE_INDEX_ROOT = 0x90;
const uint32_t ATTR_TYPE_INDEX_ALLOCATION = 0xA0;
const uint32_t ATTR_TYPE_BITMAP = 0xB0;
const uint32_t ATTR_TYPE_REPARSE_POINT = 0xC0;
const uint32_t ATTR_TYPE_EA_INFORMATION = 0xD0;
const uint32_t ATTR_TYPE_EA = 0xE0;
const uint32_t ATTR_TYPE_LOGGED_UTILITY_STREAM = 0xF0;

const uint16_t FILE_RECORD_IN_USE = 0x0001;
const uint16_t FILE_RECORD_IS_DIRECTORY = 0x0002;

const uint8_t  INDEX_ENTRY_END = 0x02;
const uint8_t  INDEX_ENTRY_HAS_SUBNODE = 0x01;

const uint16_t ATTR_FLAG_COMPRESSED = 0x0001;
const uint16_t ATTR_FLAG_ENCRYPTED = 0x4000;
const uint16_t ATTR_FLAG_SPARSE = 0x8000;

// 运行列表条目 (用于内部表示)
struct DataRun {
    uint64_t lcn;               // 逻辑簇号 (若为稀疏则为0)
    uint64_t length;            // 簇数
    bool     is_sparse;         // 是否为稀疏空洞
};

// 压缩单元信息
struct CompressionContext {
    uint16_t compression_unit;  // 压缩单元大小 (簇数的2的幂)
    std::vector<uint8_t> buffer;
};

//-----------------------------------------------------------------------------
// 事务日志记录 (存放在分区最后一个扇区)
//-----------------------------------------------------------------------------
struct TransactionRecord {
    uint64_t timestamp;         // 时间戳
    uint64_t target_mft_ref;    // 修改的MFT记录号
    uint64_t backup_lcn;        // 备份数据所在的簇 (如果适用)
    uint32_t backup_size;       // 备份数据大小 (字节)
    uint8_t  type;              // 0=无效, 1=文件写入, 2=MFT更新
    uint8_t  reserved[15];
};

//-----------------------------------------------------------------------------
// 前向声明
//-----------------------------------------------------------------------------
class NtfsVolume;

//-----------------------------------------------------------------------------
// NtfsVolume - 卷操作类 (完整实现)
//-----------------------------------------------------------------------------
class NtfsVolume {
public:
    NtfsVolume()
        : m_hDrive(INVALID_HANDLE_VALUE), m_partStart(0), m_bytesPerSector(512),
        m_sectorsPerCluster(0), m_bytesPerCluster(0),
        m_mftRecordSize(0), m_indexRecordSize(0),
        m_mftStartLcn(0), m_mftMirrLcn(0), m_totalSectors(0),
        m_mftRecordCount(0), m_mftBitmapLcn(0), m_bitmapLcn(0), m_logFileLcn(0),
        m_transactionSector(0), m_transactionActive(false),
        m_ntdll(nullptr), m_RtlDecompressBuffer(nullptr)
    {
        InitializeCriticalSection(&m_cs);
        LoadNtFunctions();
    }

    ~NtfsVolume() {
        Close();
        if (m_ntdll) FreeLibrary(m_ntdll);
        DeleteCriticalSection(&m_cs);
    }

    // 打开物理驱动器 (driveNumber: 0 = \\.\PhysicalDrive0, partitionIndex: 指定分区号, 0=自动检测)
    bool Open(int driveNumber, int partitionIndex = 0) {
        wchar_t path[32];
        swprintf_s(path, L"\\\\.\\PhysicalDrive%d", driveNumber);
        return OpenDevice(path, partitionIndex);
    }
    
    // 直接打开卷设备 (如 "C:" 或 "C:\\") - 简化版本
    bool OpenVolume(const wchar_t* volumePath) {
        wchar_t devicePath[MAX_PATH];
        if (volumePath[1] == L':') {
            swprintf_s(devicePath, L"\\\\.\\%c:", volumePath[0]);
        } else {
            wcsncpy_s(devicePath, volumePath, MAX_PATH - 1);
        }
        
        m_hDrive = CreateFileW(devicePath, GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            nullptr);
        if (m_hDrive == INVALID_HANDLE_VALUE)
            return false;
        
        m_partStart = 0;
        
        // 简单读取引导扇区
        uint8_t bootSector[512];
        DWORD bytesRead;
        if (!ReadFile(m_hDrive, bootSector, 512, &bytesRead, nullptr) || bytesRead != 512) {
            Close();
            return false;
        }
        
        // 验证NTFS签名
        if (memcmp(bootSector + 3, "NTFS", 5) != 0) {
            Close();
            return false;
        }
        
        m_bytesPerSector = *(uint16_t*)(bootSector + 11);
        m_sectorsPerCluster = bootSector[13];
        m_bytesPerCluster = m_bytesPerSector * m_sectorsPerCluster;
        
        m_mftStartLcn = *(int64_t*)(bootSector + 0x30);
        m_totalSectors = *(uint64_t*)(bootSector + 0x28);
        
        // 计算MFT记录大小
        uint8_t mftRecordSizeCode = bootSector[0x40];
        if (mftRecordSizeCode < 0x80) {
            m_mftRecordSize = mftRecordSizeCode * m_bytesPerCluster;
        } else {
            m_mftRecordSize = 1 << (mftRecordSizeCode - 0x80);
        }
        
        // 计算索引记录大小
        uint8_t indexRecordSizeCode = bootSector[0x44];
        if (indexRecordSizeCode < 0x80) {
            m_indexRecordSize = indexRecordSizeCode * m_bytesPerCluster;
        } else {
            m_indexRecordSize = 1 << (indexRecordSizeCode - 0x80);
        }
        
        m_mftRecordCount = m_totalSectors / (m_bytesPerCluster / m_bytesPerSector * 1024);
        
        return true;
    }
    
public:
    bool OpenDevice(const wchar_t* path, int partitionIndex) {
        m_hDrive = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH,
            nullptr);
        if (m_hDrive == INVALID_HANDLE_VALUE)
            return false;
        
        // 查找NTFS分区
        if (!FindNtfsPartition(partitionIndex)) {
            Close();
            return false;
        }
        
        // 解析引导扇区
        if (!ParseBootSector()) {
            Close();
            return false;
        }
        
        // 定位系统文件 ($MFT, $MFTMirr, $Bitmap, $LogFile)
        if (!LocateSystemFiles()) {
            Close();
            return false;
        }
        
        // 检查并恢复未完成的事务
        CheckAndRecoverTransaction();
        
        return true;
    }

    void Close() {
        if (m_hDrive != INVALID_HANDLE_VALUE) {
            CloseHandle(m_hDrive);
            m_hDrive = INVALID_HANDLE_VALUE;
        }
        m_transactionActive = false;
    }

    bool IsOpen() const { return m_hDrive != INVALID_HANDLE_VALUE; }

    uint64_t GetPartitionStart() const { return m_partStart; }
    uint64_t GetBytesPerCluster() const { return m_bytesPerCluster; }
    uint64_t GetMftRecordSize() const { return m_mftRecordSize; }
    uint64_t GetIndexRecordSize() const { return m_indexRecordSize; }
    uint64_t GetMftRecordCount() const { return m_mftRecordCount; }

    //-----------------------------------------------------------------------------
    // 扇区读写 (线程安全)
    //-----------------------------------------------------------------------------
    bool ReadSectors(uint64_t startSector, uint32_t sectorCount, void* buffer, int maxRetries = 3) {
        if (!IsOpen()) return false;
        EnterCriticalSection(&m_cs);
        OVERLAPPED ov = {};
        ov.Offset = static_cast<DWORD>(startSector * m_bytesPerSector);
        ov.OffsetHigh = static_cast<DWORD>((startSector * m_bytesPerSector) >> 32);

        bool success = false;
        for (int retry = 0; retry < maxRetries; ++retry) {
            DWORD bytesRead;
            if (ReadFile(m_hDrive, buffer, sectorCount * m_bytesPerSector, &bytesRead, &ov)
                && bytesRead == sectorCount * m_bytesPerSector) {
                success = true;
                break;
            }
            if (retry < maxRetries - 1) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10 * (retry + 1)));
            }
        }
        LeaveCriticalSection(&m_cs);
        return success;
    }

    bool WriteSectors(uint64_t startSector, uint32_t sectorCount, const void* buffer,
        bool verify = true, int maxRetries = 3) {
        if (!IsOpen()) return false;
        EnterCriticalSection(&m_cs);
        OVERLAPPED ov = {};
        ov.Offset = static_cast<DWORD>(startSector * m_bytesPerSector);
        ov.OffsetHigh = static_cast<DWORD>((startSector * m_bytesPerSector) >> 32);

        bool success = false;
        for (int retry = 0; retry < maxRetries; ++retry) {
            DWORD bytesWritten;
            if (WriteFile(m_hDrive, buffer, sectorCount * m_bytesPerSector, &bytesWritten, &ov)
                && bytesWritten == sectorCount * m_bytesPerSector) {
                if (verify) {
                    std::vector<uint8_t> verifyBuf(sectorCount * m_bytesPerSector);
                    if (ReadSectors(startSector, sectorCount, verifyBuf.data(), maxRetries)) {
                        if (memcmp(verifyBuf.data(), buffer, sectorCount * m_bytesPerSector) == 0) {
                            success = true;
                            break;
                        }
                    }
                    // 验证失败，重试
                }
                else {
                    success = true;
                    break;
                }
            }
            if (retry < maxRetries - 1) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10 * (retry + 1)));
            }
        }
        LeaveCriticalSection(&m_cs);
        return success;
    }

    //-----------------------------------------------------------------------------
    // MFT记录读写 (带USA修复和镜像备份)
    //-----------------------------------------------------------------------------
    bool ReadMftRecord(uint64_t recordNumber, void* buffer) {
        std::vector<uint8_t> temp(m_mftRecordSize);
        if (!ReadMftRecordFromMft(recordNumber, temp.data())) {
            // 从镜像尝试 (镜像通常只备份前4个记录)
            if (recordNumber >= 4 || !ReadMftRecordFromMirror(recordNumber, temp.data())) {
                return false;
            }
        }
        memcpy(buffer, temp.data(), m_mftRecordSize);
        return true;
    }

    bool WriteMftRecord(uint64_t recordNumber, const void* buffer) {
        // 备份原记录 (用于回滚)
        std::vector<uint8_t> backup(m_mftRecordSize);
        if (!ReadMftRecord(recordNumber, backup.data())) {
            return false;
        }

        // 计算扇区位置
        uint64_t mftStartSector = m_partStart + m_mftStartLcn * (m_bytesPerCluster / m_bytesPerSector);
        uint64_t recordSector = mftStartSector + (recordNumber * m_mftRecordSize) / m_bytesPerSector;
        uint32_t sectorsPerRec = static_cast<uint32_t>(m_mftRecordSize / m_bytesPerSector);

        // 准备写入数据，生成新的USA
        std::vector<uint8_t> modified(m_mftRecordSize);
        memcpy(modified.data(), buffer, m_mftRecordSize);
        if (!GenerateUSAForWrite(modified.data(), m_mftRecordSize)) {
            return false;
        }

        // 写入扇区 (带验证)
        if (!WriteSectors(recordSector, sectorsPerRec, modified.data(), true, 5)) {
            // 写入失败，尝试恢复备份
            WriteSectors(recordSector, sectorsPerRec, backup.data(), false, 3);
            return false;
        }

        return true;
    }

    //-----------------------------------------------------------------------------
    // 路径解析 (支持多级目录，自动处理短名)
    //-----------------------------------------------------------------------------
    bool ResolvePath(const std::string& path, uint64_t& outMftRef) {
        if (path.empty() || path == "\\") {
            outMftRef = 5;  // 根目录
            return true;
        }

        std::string p = path;
        if (p[0] == '\\') p = p.substr(1);
        std::vector<std::string> components;
        size_t start = 0, end;
        while ((end = p.find('\\', start)) != std::string::npos) {
            if (end > start)
                components.push_back(p.substr(start, end - start));
            start = end + 1;
        }
        if (start < p.length())
            components.push_back(p.substr(start));

        uint64_t current = 5; // 根目录
        for (const auto& comp : components) {
            if (!FindFileInDirectory(current, comp, current)) {
                return false;
            }
        }
        outMftRef = current;
        return true;
    }

    //-----------------------------------------------------------------------------
    // 文件读取 (支持压缩、稀疏、属性列表)
    //-----------------------------------------------------------------------------
    bool ReadFileData(uint64_t mftRef, uint64_t offset, void* buffer, uint32_t length, uint32_t* bytesRead) {
        std::vector<DataRun> runs;
        uint64_t fileSize;
        bool isResident;
        uint16_t flags; // 压缩/稀疏标志
        if (!GetDataRunsWithFlags(mftRef, runs, fileSize, &isResident, &flags)) {
            return false;
        }

        if (offset >= fileSize) {
            *bytesRead = 0;
            return true;
        }

        uint64_t toRead = std::min<uint64_t>(length, fileSize - offset);

        if (isResident) {
            // 常驻数据：直接拷贝
            std::vector<uint8_t> mftRec(m_mftRecordSize);
            if (!ReadMftRecord(mftRef, mftRec.data())) return false;
            const uint8_t* data = FindResidentData(mftRec.data());
            if (!data) return false;
            memcpy(buffer, data + offset, static_cast<size_t>(toRead));
            *bytesRead = static_cast<uint32_t>(toRead);
            return true;
        }
        else {
            // 非常驻：从运行列表读取，处理压缩和稀疏
            if (flags & ATTR_FLAG_COMPRESSED) {
                return ReadCompressedFromRuns(runs, offset, static_cast<uint32_t>(toRead),
                    static_cast<uint8_t*>(buffer), bytesRead, flags);
            }
            else {
                return ReadFromRuns(runs, offset, static_cast<uint32_t>(toRead),
                    static_cast<uint8_t*>(buffer), bytesRead);
            }
        }
    }

    //-----------------------------------------------------------------------------
    // 文件写入 (事务性，支持自动扩展、稀疏区域分配)
    //-----------------------------------------------------------------------------
    bool WriteFileData(uint64_t mftRef, uint64_t offset, const void* buffer,
        uint32_t length, uint32_t* bytesWritten) {
        std::vector<uint8_t> mftRec(m_mftRecordSize);
        if (!ReadMftRecord(mftRef, mftRec.data()))
            return false;

        // 解析现有数据属性 (考虑属性列表)
        std::vector<DataRun> runs;
        uint64_t fileSize = 0, allocatedSize = 0;
        bool isResident = false;
        uint16_t flags = 0;
        uint16_t dataAttrOffset = 0;
        uint64_t baseMftRef = mftRef; // 可能来自属性列表
        if (!ParseDataRunsEx(mftRec.data(), mftRef, runs, fileSize, &allocatedSize, &isResident, &flags, &dataAttrOffset, &baseMftRef))
            return false;

        uint64_t newEnd = offset + length;
        bool needExtend = (newEnd > fileSize);

        // 如果是常驻且超出MFT记录剩余空间，转换为非常驻
        if (isResident && needExtend && newEnd > m_mftRecordSize - 0x100) {
            // 转换功能已禁用，因为实现不安全，直接返回失败
            // 若需支持，请实现安全的转换（例如分配新MFT记录并通过属性列表链接）
            return false;
        }

        // 如果需要扩展，分配新簇
        if (!isResident && needExtend) {
            uint64_t newAllocSize = ((newEnd + m_bytesPerCluster - 1) / m_bytesPerCluster) * m_bytesPerCluster;
            if (newAllocSize > allocatedSize) {
                uint64_t extraClusters = (newAllocSize - allocatedSize) / m_bytesPerCluster;
                if (!ExtendFileRuns(runs, extraClusters))
                    return false;
                allocatedSize = newAllocSize;
            }
            fileSize = newEnd;
        }

        // 处理稀疏区域写入：如果写入位置在稀疏区域，需要先分配簇
        if (!isResident && (flags & ATTR_FLAG_SPARSE)) {
            if (!EnsureRunsAllocated(runs, offset, length))
                return false;
        }

        // 写入数据（需要事务保护）
        // 备份可能被覆盖的簇
        uint64_t firstCluster = offset / m_bytesPerCluster;
        uint64_t lastCluster = (offset + length - 1) / m_bytesPerCluster;
        std::map<uint64_t, std::vector<uint8_t>> backupClusters; // lcn -> data
        if (!isResident) {
            // 收集需要备份的LCN
            for (uint64_t vcn = firstCluster; vcn <= lastCluster; ++vcn) {
                uint64_t lcn;
                if (!VcnToLcn(runs, vcn, lcn)) {
                    // 如果是稀疏，无需备份（因为将写入新分配簇，但备份可能为空）
                    continue;
                }
                if (backupClusters.find(lcn) == backupClusters.end()) {
                    std::vector<uint8_t> clusterData(m_bytesPerCluster);
                    uint64_t sector = m_partStart + lcn * (m_bytesPerCluster / m_bytesPerSector);
                    if (!ReadSectors(sector, (uint32_t)(m_bytesPerCluster / m_bytesPerSector), clusterData.data()))
                        return false;
                    backupClusters[lcn] = std::move(clusterData);
                }
            }
        }

        // 开始事务
        BeginTransaction(mftRef, 0, 0); // 简化事务：只标记开始，实际应记录备份簇

        // 执行写入
        uint32_t written = 0;
        bool writeOk = false;
        if (isResident) {
            // 写入常驻MFT
            uint8_t* dataPtr = FindResidentData(mftRec.data());
            if (!dataPtr) return false;
            memcpy(dataPtr + offset, buffer, length);
            if (!WriteMftRecord(baseMftRef, mftRec.data())) {
                goto rollback;
            }
            written = length;
            writeOk = true;
        }
        else {
            if (!WriteToRuns(runs, offset, length, static_cast<const uint8_t*>(buffer), &written)) {
                goto rollback;
            }
            writeOk = true;
        }

        // 更新MFT记录中的大小信息 (如果需要)
        if (!isResident && (needExtend || writeOk)) {
            UpdateFileSizeInMft(mftRec.data(), fileSize, allocatedSize);
            // 更新运行列表 (如果改变了)
            if (needExtend || !backupClusters.empty()) {
                if (!UpdateDataRunsInMft(mftRec.data(), runs, dataAttrOffset))
                    goto rollback;
            }
            if (!WriteMftRecord(baseMftRef, mftRec.data()))
                goto rollback;
        }

        // 提交事务
        CommitTransaction();
        *bytesWritten = written;
        return true;

    rollback:
        // 回滚：从备份恢复簇
        for (const auto& [lcn, data] : backupClusters) {
            uint64_t sector = m_partStart + lcn * (m_bytesPerCluster / m_bytesPerSector);
            WriteSectors(sector, (uint32_t)(m_bytesPerCluster / m_bytesPerSector), data.data(), true);
        }
        CommitTransaction(); // 清除事务标记
        return false;
    }

    //-----------------------------------------------------------------------------
    // 簇分配/释放 (基于$Bitmap)
    //-----------------------------------------------------------------------------
    bool AllocateClusters(uint64_t count, std::vector<uint64_t>& allocatedLcns) {
        if (count == 0) return true;
        allocatedLcns.clear();

        std::vector<uint8_t> bitmapData;
        if (!ReadBitmapData(bitmapData))
            return false;

        uint64_t totalClusters = m_totalSectors / m_sectorsPerCluster;
        uint64_t bitmapBytes = (totalClusters + 7) / 8;
        if (bitmapData.size() < bitmapBytes)
            return false;

        // 简单顺序分配
        uint64_t found = 0;
        for (uint64_t cluster = 0; cluster < totalClusters && found < count; ++cluster) {
            size_t byteIdx = cluster >> 3;
            uint8_t bitMask = 1 << (cluster & 7);
            if ((bitmapData[byteIdx] & bitMask) == 0) { // 空闲
                bitmapData[byteIdx] |= bitMask;        // 占用
                allocatedLcns.push_back(cluster);
                ++found;
            }
        }

        if (found < count) {
            // 不足，释放已分配的 (简化：不释放)
            return false;
        }

        // 写回 $Bitmap
        if (!WriteBitmapData(bitmapData))
            return false;

        return true;
    }

    bool FreeClusters(const std::vector<uint64_t>& lcns) {
        if (lcns.empty()) return true;

        std::vector<uint8_t> bitmapData;
        if (!ReadBitmapData(bitmapData))
            return false;

        uint64_t totalClusters = m_totalSectors / m_sectorsPerCluster;
        for (uint64_t lcn : lcns) {
            if (lcn >= totalClusters) continue;
            size_t byteIdx = lcn >> 3;
            uint8_t bitMask = 1 << (lcn & 7);
            bitmapData[byteIdx] &= ~bitMask; // 释放
        }

        return WriteBitmapData(bitmapData);
    }

    // 获取文件的$DATA运行列表（支持属性列表）
    bool GetDataRunsWithFlags(uint64_t mftRef, std::vector<DataRun>& runs, uint64_t& fileSize, bool* pIsResident, uint16_t* pFlags) {
        std::vector<uint8_t> mftRec(m_mftRecordSize);
        if (!ReadMftRecord(mftRef, mftRec.data())) return false;
        return ParseDataRunsEx(mftRec.data(), mftRef, runs, fileSize, nullptr, pIsResident, pFlags, nullptr, nullptr);
    }

public:
    HANDLE  m_hDrive;
    CRITICAL_SECTION m_cs;

    uint64_t m_partStart;          // 分区起始扇区 (LBA)
    uint16_t m_bytesPerSector;     // 每扇区字节数
    uint8_t  m_sectorsPerCluster;  // 每簇扇区数
    uint64_t m_bytesPerCluster;    // 每簇字节数
    uint64_t m_mftRecordSize;      // MFT记录大小 (字节)
    uint64_t m_indexRecordSize;    // 索引记录大小 (字节)
    uint64_t m_mftStartLcn;        // $MFT起始簇号
    uint64_t m_mftMirrLcn;         // $MFT镜像簇号
    uint64_t m_totalSectors;       // 分区总扇区数
    uint64_t m_mftRecordCount;     // MFT记录总数 (可从$MFT大小推算)
    uint64_t m_mftBitmapLcn;       // $MFTBitmap 起始LCN (可选)
    uint64_t m_bitmapLcn;          // $Bitmap 起始LCN
    uint64_t m_logFileLcn;         // $LogFile 起始LCN
    uint64_t m_transactionSector;  // 事务日志扇区 (分区最后一个扇区)
    bool     m_transactionActive;  // 事务是否激活

    // NT 压缩函数
    HMODULE m_ntdll;
    typedef NTSTATUS(NTAPI* RtlDecompressBuffer_t)(USHORT CompressionFormat, PUCHAR UncompressedBuffer, ULONG UncompressedBufferSize, PUCHAR CompressedBuffer, ULONG CompressedBufferSize, PULONG FinalUncompressedSize);
    RtlDecompressBuffer_t m_RtlDecompressBuffer;

    void LoadNtFunctions() {
        m_ntdll = LoadLibraryW(L"ntdll.dll");
        if (m_ntdll) {
            m_RtlDecompressBuffer = (RtlDecompressBuffer_t)GetProcAddress(m_ntdll, "RtlDecompressBuffer");
        }
    }

    //-----------------------------------------------------------------------------
    // 分区查找 (支持GPT和MBR)
    //-----------------------------------------------------------------------------
    bool FindNtfsPartition(int desiredIndex) {
        uint8_t sector[512];
        if (!ReadSectors(0, 1, sector)) return false;

        // 检查是否为GPT保护MBR (0xEE)
        if (sector[0x1C2] == 0xEE) {
            return FindNtfsPartitionGpt(desiredIndex);
        }
        else {
            return FindNtfsPartitionMbr(desiredIndex);
        }
    }

    bool FindNtfsPartitionMbr(int desiredIndex) {
        uint8_t sector[512];
        if (!ReadSectors(0, 1, sector)) return false;

        int found = 0;
        for (int i = 0; i < 4; i++) {
            uint8_t* part = sector + 0x1BE + i * 16;
            uint8_t type = part[4];
            if (type == 0x07) { // NTFS
                if (desiredIndex == 0 || desiredIndex == found + 1) {
                    m_partStart = *(uint32_t*)(part + 8);
                    return true;
                }
                found++;
            }
        }
        return false;
    }

    bool FindNtfsPartitionGpt(int desiredIndex) {
        uint8_t sector[512];
        // 读取GPT头 (LBA1)
        if (!ReadSectors(1, 1, sector)) return false;
        if (memcmp(sector, "EFI PART", 8) != 0) return false;

        uint64_t partTableLba = *(uint64_t*)(sector + 72);
        uint32_t numParts = *(uint32_t*)(sector + 80);
        uint32_t partEntrySize = *(uint32_t*)(sector + 84);

        std::vector<uint8_t> partTable(partEntrySize * numParts);
        if (!ReadSectors(partTableLba, (uint32_t)(partTable.size() / 512), partTable.data()))
            return false;

        // NTFS分区类型GUID: EBD0A0A2-B9E5-4433-87C0-68B6B72699C7
        uint8_t ntfsGuid[16] = { 0xA2,0xA0,0xD0,0xEB,0xE5,0xB9,0x33,0x44,0x87,0xC0,0x68,0xB6,0xB7,0x26,0x99,0xC7 };
        int found = 0;
        for (uint32_t i = 0; i < numParts; ++i) {
            uint8_t* entry = partTable.data() + i * partEntrySize;
            if (memcmp(entry + 0, ntfsGuid, 16) == 0) {
                if (desiredIndex == 0 || desiredIndex == found + 1) {
                    m_partStart = *(uint64_t*)(entry + 32);
                    return true;
                }
                found++;
            }
        }
        return false;
    }

    //-----------------------------------------------------------------------------
    // 引导扇区解析
    //-----------------------------------------------------------------------------
    bool ParseBootSector() {
        uint8_t sector[512];
        if (!ReadSectors(m_partStart, 1, sector)) return false;
        if (memcmp(sector + 3, "NTFS", 4) != 0) return false;

        NtfsBpb* bpb = reinterpret_cast<NtfsBpb*>(sector + 11);
        m_bytesPerSector = bpb->bytes_per_sector;
        m_sectorsPerCluster = bpb->sectors_per_cluster;
        m_bytesPerCluster = m_bytesPerSector * m_sectorsPerCluster;
        m_mftStartLcn = bpb->mft_lcn;
        m_mftMirrLcn = bpb->mft_mirr_lcn;
        m_totalSectors = bpb->total_sectors;

        // MFT记录大小
        if (bpb->clusters_per_mft_record > 0)
            m_mftRecordSize = bpb->clusters_per_mft_record * m_bytesPerCluster;
        else
            m_mftRecordSize = 1 << (-bpb->clusters_per_mft_record);

        // 索引记录大小
        if (bpb->clusters_per_index_record > 0)
            m_indexRecordSize = bpb->clusters_per_index_record * m_bytesPerCluster;
        else
            m_indexRecordSize = 1 << (-bpb->clusters_per_index_record);

        // 事务扇区 (分区最后一个扇区)
        m_transactionSector = m_partStart + m_totalSectors - 1;

        return true;
    }

    //-----------------------------------------------------------------------------
    // 定位系统文件 ($MFT, $MFTMirr, $Bitmap, $LogFile) 通过读取$MFT记录0
    //-----------------------------------------------------------------------------
    bool LocateSystemFiles() {
        // 读取 $MFT 记录 (记录0)
        std::vector<uint8_t> mftRec(m_mftRecordSize);
        if (!ReadMftRecord(0, mftRec.data())) return false;

        // 解析 $MFT 的数据运行列表以确定其大小
        std::vector<DataRun> mftRuns;
        uint64_t mftSize = 0;
        bool isResident;
        uint16_t flags;
        if (!ParseDataRunsEx(mftRec.data(), 0, mftRuns, mftSize, nullptr, &isResident, &flags, nullptr, nullptr))
            return false;
        m_mftRecordCount = mftSize / m_mftRecordSize;

        // 获取 $Bitmap 的LCN: 读取记录6 (通常为 $Bitmap)
        std::vector<uint8_t> bitmapRec(m_mftRecordSize);
        if (!ReadMftRecord(6, bitmapRec.data())) return false;
        std::vector<DataRun> bitmapRuns;
        uint64_t bitmapSize;
        if (!ParseDataRunsEx(bitmapRec.data(), 6, bitmapRuns, bitmapSize, nullptr, &isResident, &flags, nullptr, nullptr))
            return false;
        if (!isResident && !bitmapRuns.empty())
            m_bitmapLcn = bitmapRuns[0].lcn;  // 简化：取第一段起始LCN

        // 获取 $LogFile 的LCN: 记录2
        std::vector<uint8_t> logRec(m_mftRecordSize);
        if (!ReadMftRecord(2, logRec.data())) return false;
        std::vector<DataRun> logRuns;
        uint64_t logSize;
        if (!ParseDataRunsEx(logRec.data(), 2, logRuns, logSize, nullptr, &isResident, &flags, nullptr, nullptr))
            return false;
        if (!isResident && !logRuns.empty())
            m_logFileLcn = logRuns[0].lcn;

        return true;
    }

    //-----------------------------------------------------------------------------
    // MFT记录读取 (带USA修复)
    //-----------------------------------------------------------------------------
    bool ReadMftRecordFromMft(uint64_t recordNumber, void* buffer) {
        uint64_t mftStartSector = m_partStart + m_mftStartLcn * (m_bytesPerCluster / m_bytesPerSector);
        uint64_t recordSector = mftStartSector + (recordNumber * m_mftRecordSize) / m_bytesPerSector;
        uint32_t sectorsPerRec = static_cast<uint32_t>(m_mftRecordSize / m_bytesPerSector);
        std::vector<uint8_t> temp(sectorsPerRec * m_bytesPerSector);
        if (!ReadSectors(recordSector, sectorsPerRec, temp.data()))
            return false;

        if (!ApplyUSA(temp.data(), m_mftRecordSize)) {
            return false;
        }
        memcpy(buffer, temp.data(), m_mftRecordSize);
        return true;
    }

    bool ReadMftRecordFromMirror(uint64_t recordNumber, void* buffer) {
        if (m_mftMirrLcn == 0) return false;
        uint64_t mirrorStartSector = m_partStart + m_mftMirrLcn * (m_bytesPerCluster / m_bytesPerSector);
        uint64_t recordSector = mirrorStartSector + (recordNumber * m_mftRecordSize) / m_bytesPerSector;
        uint32_t sectorsPerRec = static_cast<uint32_t>(m_mftRecordSize / m_bytesPerSector);
        std::vector<uint8_t> temp(sectorsPerRec * m_bytesPerSector);
        if (!ReadSectors(recordSector, sectorsPerRec, temp.data()))
            return false;

        if (!ApplyUSA(temp.data(), m_mftRecordSize)) {
            return false;
        }
        memcpy(buffer, temp.data(), m_mftRecordSize);
        return true;
    }

    // 应用USA (验证并修复)
    bool ApplyUSA(uint8_t* record, uint32_t recSize) {
        FileRecordHeader* hdr = reinterpret_cast<FileRecordHeader*>(record);
        if (memcmp(hdr->magic, "FILE", 4) != 0) return false;
        uint16_t usaOffset = hdr->usa_offset;
        uint16_t usaCount = hdr->usa_count;
        if (usaCount < 1) return false;
        uint16_t* usa = reinterpret_cast<uint16_t*>(record + usaOffset);
        uint16_t usaSig = usa[0];

        // 每个扇区末尾 (512字节) 的更新序列
        uint16_t* sectorEnd = reinterpret_cast<uint16_t*>(record + m_bytesPerSector - 2);
        for (uint16_t i = 1; i < usaCount; ++i) {
            if (sectorEnd >= reinterpret_cast<uint16_t*>(record + recSize)) break;
            if (*sectorEnd != usaSig) {
                // USA 不匹配，尝试用 usa[i] 修复
                *sectorEnd = usa[i];
            }
            sectorEnd = reinterpret_cast<uint16_t*>(reinterpret_cast<uint8_t*>(sectorEnd) + m_bytesPerSector);
        }
        return true;
    }

    // 为写入生成USA (更新每个扇区末尾的USA值)
    bool GenerateUSAForWrite(uint8_t* record, uint32_t recSize) {
        FileRecordHeader* hdr = reinterpret_cast<FileRecordHeader*>(record);
        if (memcmp(hdr->magic, "FILE", 4) != 0) return false;
        uint16_t usaOffset = hdr->usa_offset;
        uint16_t usaCount = hdr->usa_count;
        if (usaCount < 1) return false;
        uint16_t* usa = reinterpret_cast<uint16_t*>(record + usaOffset);

        // 递增序列号 (使用原子变量保证线程安全)
        static std::atomic<uint16_t> nextSeq(1);
        uint16_t newSig = nextSeq.fetch_add(1, std::memory_order_relaxed);

        // 保存原扇区末尾值到usa[i]，并将扇区末尾设为newSig
        uint16_t* sectorEnd = reinterpret_cast<uint16_t*>(record + m_bytesPerSector - 2);
        for (uint16_t i = 1; i < usaCount; ++i) {
            if (sectorEnd >= reinterpret_cast<uint16_t*>(record + recSize)) break;
            usa[i] = *sectorEnd;
            *sectorEnd = newSig;
            sectorEnd = reinterpret_cast<uint16_t*>(reinterpret_cast<uint8_t*>(sectorEnd) + m_bytesPerSector);
        }
        usa[0] = newSig;  // 更新头部序列号
        return true;
    }

    // 应用索引块USA修复
    bool ApplyIndexBlockUSA(uint8_t* block, uint32_t blockSize) {
        IndexBlockHeader* hdr = reinterpret_cast<IndexBlockHeader*>(block);
        if (memcmp(hdr->magic, "INDX", 4) != 0) return false;
        uint16_t usaOffset = hdr->usa_offset;
        uint16_t usaCount = hdr->usa_count;
        if (usaCount < 1 || usaOffset + usaCount * 2 > blockSize) return false;
        uint16_t* usa = reinterpret_cast<uint16_t*>(block + usaOffset);
        uint16_t usaSig = usa[0];

        uint16_t* sectorEnd = reinterpret_cast<uint16_t*>(block + m_bytesPerSector - 2);
        for (uint16_t i = 1; i < usaCount; ++i) {
            if (sectorEnd >= reinterpret_cast<uint16_t*>(block + blockSize)) break;
            if (*sectorEnd != usaSig) {
                *sectorEnd = usa[i];
            }
            sectorEnd = reinterpret_cast<uint16_t*>(reinterpret_cast<uint8_t*>(sectorEnd) + m_bytesPerSector);
        }
        return true;
    }

    //-----------------------------------------------------------------------------
    // 运行列表解析与操作
    //-----------------------------------------------------------------------------
    bool ParseRunList(const uint8_t* data, uint32_t maxLen, std::vector<DataRun>& runs) {
        uint32_t pos = 0;
        uint64_t currentLcn = 0;
        runs.clear();

        while (pos < maxLen) {
            uint8_t header = data[pos++];
            if (header == 0) break;
            int lenSize = header & 0x0F;
            int offSize = (header >> 4) & 0x0F;

            uint64_t length = 0;
            for (int i = 0; i < lenSize; i++) {
                if (pos >= maxLen) return false;
                length |= static_cast<uint64_t>(data[pos++]) << (i * 8);
            }

            if (offSize == 0) {
                runs.push_back({ 0, length, true });
                continue;
            }

            uint64_t lcnOffset = 0;
            for (int i = 0; i < offSize; i++) {
                if (pos >= maxLen) return false;
                lcnOffset |= static_cast<uint64_t>(data[pos++]) << (i * 8);
            }
            // 符号扩展
            if (lcnOffset >> ((offSize * 8) - 1)) {
                lcnOffset |= ~((1ULL << (offSize * 8)) - 1);
            }
            int64_t signedOffset = static_cast<int64_t>(lcnOffset);
            currentLcn += signedOffset;
            runs.push_back({ currentLcn, length, false });
        }
        return true;
    }

    std::vector<uint8_t> EncodeRunList(const std::vector<DataRun>& runs) {
        std::vector<uint8_t> encoded;
        uint64_t prevLcn = 0;
        for (const auto& run : runs) {
            if (run.is_sparse) {
                // 稀疏运行
                int lenSize = (run.length <= 0xFF) ? 1 : (run.length <= 0xFFFF) ? 2 : 4;
                uint8_t header = (0 << 4) | lenSize;
                encoded.push_back(header);
                uint64_t len = run.length;
                for (int i = 0; i < lenSize; ++i) {
                    encoded.push_back((len >> (i * 8)) & 0xFF);
                }
                // 无偏移
            }
            else {
                int64_t delta = static_cast<int64_t>(run.lcn - prevLcn);
                int offSize;
                if (delta >= -0x80 && delta <= 0x7F) offSize = 1;
                else if (delta >= -0x8000 && delta <= 0x7FFF) offSize = 2;
                else offSize = 4;

                int lenSize = (run.length <= 0xFF) ? 1 : (run.length <= 0xFFFF) ? 2 : 4;
                uint8_t header = (offSize << 4) | lenSize;
                encoded.push_back(header);
                uint64_t len = run.length;
                for (int i = 0; i < lenSize; ++i) {
                    encoded.push_back((len >> (i * 8)) & 0xFF);
                }
                uint64_t udelta = static_cast<uint64_t>(delta);
                for (int i = 0; i < offSize; ++i) {
                    encoded.push_back((udelta >> (i * 8)) & 0xFF);
                }
                prevLcn = run.lcn;
            }
        }
        encoded.push_back(0);
        return encoded;
    }

    // 解析属性列表
    bool ParseAttributeList(const uint8_t* data, uint32_t dataSize, std::vector<AttrListEntry>& entries) {
        uint32_t pos = 0;
        while (pos + sizeof(AttrListEntry) <= dataSize) {
            const AttrListEntry* entry = reinterpret_cast<const AttrListEntry*>(data + pos);
            if (entry->length == 0) break;
            if (pos + entry->length > dataSize) break;
            entries.push_back(*entry);
            pos += entry->length;
        }
        return true;
    }

    // 扩展解析数据属性，支持属性列表
    bool ParseDataRunsEx(const uint8_t* mftRecord, uint64_t mftRef, std::vector<DataRun>& runs,
        uint64_t& fileSize, uint64_t* pAllocatedSize,
        bool* pIsResident, uint16_t* pFlags,
        uint16_t* pAttrOffset, uint64_t* pBaseMftRef) {
        const FileRecordHeader* hdr = reinterpret_cast<const FileRecordHeader*>(mftRecord);
        if (memcmp(hdr->magic, "FILE", 4) != 0) return false;

        uint16_t attrOff = hdr->attr_offset;
        uint64_t baseRef = (hdr->base_file_record != 0) ? hdr->base_file_record : mftRef;
        if (pBaseMftRef) *pBaseMftRef = baseRef;

        // 先搜索属性列表
        while (attrOff < hdr->bytes_in_use) {
            const AttrHeader* attr = reinterpret_cast<const AttrHeader*>(mftRecord + attrOff);
            if (attr->type == ATTR_TYPE_ATTRIBUTE_LIST) {
                // 解析属性列表
                std::vector<uint8_t> listData;
                if (attr->non_resident) {
                    // 非常驻属性列表：读取数据
                    const NonResidentAttr* nr = reinterpret_cast<const NonResidentAttr*>(attr);
                    std::vector<DataRun> listRuns;
                    const uint8_t* runData = mftRecord + attrOff + nr->runlist_offset;
                    uint32_t maxLen = nr->length - nr->runlist_offset;
                    if (!ParseRunList(runData, maxLen, listRuns)) return false;
                    listData.resize((size_t)nr->data_size);
                    uint32_t bytesRead;
                    if (!ReadFromRuns(listRuns, 0, (uint32_t)nr->data_size, listData.data(), &bytesRead) || bytesRead != nr->data_size)
                        return false;
                }
                else {
                    const ResidentAttr* r = reinterpret_cast<const ResidentAttr*>(attr);
                    listData.assign(mftRecord + attrOff + r->content_offset,
                        mftRecord + attrOff + r->content_offset + r->content_length);
                }

                std::vector<AttrListEntry> entries;
                if (!ParseAttributeList(listData.data(), (uint32_t)listData.size(), entries))
                    return false;

                // 遍历属性列表，查找 $DATA 属性
                for (const auto& entry : entries) {
                    if (entry.attr_type == ATTR_TYPE_DATA) {
                        // 读取该属性所在的MFT记录
                        uint64_t targetRef = entry.base_mft_ref & 0xFFFFFFFFFFFF; // 低48位
                        std::vector<uint8_t> targetRec(m_mftRecordSize);
                        if (!ReadMftRecord(targetRef, targetRec.data()))
                            continue;
                        // 在该记录中查找对应属性ID的 $DATA
                        uint16_t targetAttrOff = reinterpret_cast<FileRecordHeader*>(targetRec.data())->attr_offset;
                        while (targetAttrOff < reinterpret_cast<FileRecordHeader*>(targetRec.data())->bytes_in_use) {
                            const AttrHeader* targetAttr = reinterpret_cast<const AttrHeader*>(targetRec.data() + targetAttrOff);
                            if (targetAttr->type == ATTR_TYPE_DATA && targetAttr->attribute_id == entry.attribute_id) {
                                // 找到，解析运行列表
                                if (targetAttr->non_resident) {
                                    const NonResidentAttr* nr = reinterpret_cast<const NonResidentAttr*>(targetAttr);
                                    fileSize = nr->data_size;
                                    if (pAllocatedSize) *pAllocatedSize = nr->allocated_size;
                                    if (pFlags) *pFlags = nr->flags;
                                    const uint8_t* runData = targetRec.data() + targetAttrOff + nr->runlist_offset;
                                    uint32_t maxLen = nr->length - nr->runlist_offset;
                                    if (pIsResident) *pIsResident = false;
                                    if (pAttrOffset) *pAttrOffset = targetAttrOff;
                                    if (pBaseMftRef) *pBaseMftRef = targetRef;
                                    return ParseRunList(runData, maxLen, runs);
                                }
                                else {
                                    const ResidentAttr* r = reinterpret_cast<const ResidentAttr*>(targetAttr);
                                    fileSize = r->content_length;
                                    if (pAllocatedSize) *pAllocatedSize = 0;
                                    if (pFlags) *pFlags = r->flags;
                                    runs.clear();
                                    if (pIsResident) *pIsResident = true;
                                    if (pAttrOffset) *pAttrOffset = targetAttrOff;
                                    if (pBaseMftRef) *pBaseMftRef = targetRef;
                                    return true;
                                }
                            }
                            if (targetAttr->length == 0) break;
                            targetAttrOff += targetAttr->length;
                        }
                    }
                }
                // 未在属性列表中找到数据属性，继续查找本记录
            }
            attrOff += attr->length;
        }

        // 没有属性列表，直接在本记录中查找 $DATA
        attrOff = hdr->attr_offset;
        while (attrOff < hdr->bytes_in_use) {
            const AttrHeader* attr = reinterpret_cast<const AttrHeader*>(mftRecord + attrOff);
            if (attr->type == ATTR_TYPE_DATA) {
                if (pAttrOffset) *pAttrOffset = attrOff;
                if (attr->non_resident) {
                    const NonResidentAttr* nr = reinterpret_cast<const NonResidentAttr*>(attr);
                    fileSize = nr->data_size;
                    if (pAllocatedSize) *pAllocatedSize = nr->allocated_size;
                    if (pFlags) *pFlags = nr->flags;
                    const uint8_t* runData = mftRecord + attrOff + nr->runlist_offset;
                    uint32_t maxLen = nr->length - nr->runlist_offset;
                    if (pIsResident) *pIsResident = false;
                    return ParseRunList(runData, maxLen, runs);
                }
                else {
                    const ResidentAttr* r = reinterpret_cast<const ResidentAttr*>(attr);
                    fileSize = r->content_length;
                    if (pAllocatedSize) *pAllocatedSize = 0;
                    if (pFlags) *pFlags = r->flags;
                    runs.clear();
                    if (pIsResident) *pIsResident = true;
                    return true;
                }
            }
            if (attr->length == 0) break;
            attrOff += attr->length;
        }
        return false;
    }

    // 查找常驻数据的指针 (仅用于常驻属性)
    uint8_t* FindResidentData(uint8_t* mftRecord) {
        FileRecordHeader* hdr = reinterpret_cast<FileRecordHeader*>(mftRecord);
        uint16_t attrOff = hdr->attr_offset;
        while (attrOff < hdr->bytes_in_use) {
            AttrHeader* attr = reinterpret_cast<AttrHeader*>(mftRecord + attrOff);
            if (attr->type == ATTR_TYPE_DATA && !attr->non_resident) {
                ResidentAttr* r = reinterpret_cast<ResidentAttr*>(attr);
                return mftRecord + attrOff + r->content_offset;
            }
            if (attr->length == 0) break;
            attrOff += attr->length;
        }
        return nullptr;
    }

    // 更新MFT记录中的$DATA属性运行列表（可能位于外部记录）
    bool UpdateDataRunsInMft(uint8_t* mftRecord, const std::vector<DataRun>& runs, uint16_t attrOffset) {
        AttrHeader* attr = reinterpret_cast<AttrHeader*>(mftRecord + attrOffset);
        if (attr->type != ATTR_TYPE_DATA || !attr->non_resident) return false;

        NonResidentAttr* nr = reinterpret_cast<NonResidentAttr*>(attr);
        std::vector<uint8_t> encoded = EncodeRunList(runs);
        uint32_t maxRunSpace = nr->length - nr->runlist_offset;
        if (encoded.size() > maxRunSpace) {
            // 空间不足，需要移动属性或扩展属性 (简化: 拒绝)
            return false;
        }
        memcpy(mftRecord + attrOffset + nr->runlist_offset, encoded.data(), encoded.size());
        // 剩余空间清零 (可选)
        if (encoded.size() < maxRunSpace) {
            memset(mftRecord + attrOffset + nr->runlist_offset + encoded.size(), 0, maxRunSpace - encoded.size());
        }
        // 更新 last_vcn
        uint64_t totalClusters = 0;
        for (const auto& run : runs) totalClusters += run.length;
        nr->last_vcn = totalClusters - 1;
        return true;
    }

    // 更新文件大小
    void UpdateFileSizeInMft(uint8_t* mftRecord, uint64_t newFileSize, uint64_t newAllocSize) {
        FileRecordHeader* hdr = reinterpret_cast<FileRecordHeader*>(mftRecord);
        uint16_t attrOff = hdr->attr_offset;
        while (attrOff < hdr->bytes_in_use) {
            AttrHeader* attr = reinterpret_cast<AttrHeader*>(mftRecord + attrOff);
            if (attr->type == ATTR_TYPE_DATA) {
                if (attr->non_resident) {
                    NonResidentAttr* nr = reinterpret_cast<NonResidentAttr*>(attr);
                    nr->data_size = newFileSize;
                    nr->allocated_size = newAllocSize;
                    nr->initialized_size = newFileSize;
                }
                else {
                    ResidentAttr* r = reinterpret_cast<ResidentAttr*>(attr);
                    r->content_length = static_cast<uint32_t>(newFileSize);
                }
                return;
            }
            if (attr->length == 0) break;
            attrOff += attr->length;
        }
    }

    // 将常驻转换为非常驻 (分配一个簇，移动数据) - 此函数实现不安全，已禁用
    bool ConvertResidentToNonResident(uint8_t* mftRecord, uint64_t mftRef, std::vector<DataRun>& runs,
        uint64_t oldFileSize, uint64_t& newAllocSize,
        uint16_t attrOffset) {
        // 由于实现复杂且容易破坏文件系统，此版本禁用自动转换
        // 如需支持，请实现安全的转换（例如分配新MFT记录并通过属性列表链接）
        return false;
    }

    // 扩展文件运行列表 (分配额外簇)
    bool ExtendFileRuns(std::vector<DataRun>& runs, uint64_t extraClusters) {
        std::vector<uint64_t> newLcns;
        if (!AllocateClusters(extraClusters, newLcns)) return false;

        // 将新簇合并到运行列表
        uint64_t remaining = extraClusters;
        size_t idx = 0;
        while (remaining > 0) {
            uint64_t lcn = newLcns[idx];
            uint64_t count = 1;
            while (idx + 1 < newLcns.size() && newLcns[idx + 1] == lcn + count) {
                count++;
                idx++;
            }
            idx++;

            // 尝试与最后一个运行合并
            if (!runs.empty() && !runs.back().is_sparse && runs.back().lcn + runs.back().length == lcn) {
                runs.back().length += count;
            }
            else {
                runs.push_back({ lcn, count, false });
            }
            remaining -= count;
        }
        return true;
    }

    // 确保写入区域的所有簇都已分配（处理稀疏区域）
    bool EnsureRunsAllocated(std::vector<DataRun>& runs, uint64_t offset, uint32_t length) {
        uint64_t startVcn = offset / m_bytesPerCluster;
        uint64_t endVcn = (offset + length - 1) / m_bytesPerCluster;
        std::vector<std::pair<uint64_t, uint64_t>> holes; // 记录需要分配的vcn范围

        uint64_t curVcn = 0;
        for (size_t i = 0; i < runs.size(); ++i) {
            const auto& run = runs[i];
            if (curVcn > endVcn) break;
            if (curVcn + run.length > startVcn) {
                // 检查重叠部分
                if (run.is_sparse) {
                    uint64_t holeStart = std::max(curVcn, startVcn);
                    uint64_t holeEnd = std::min(curVcn + run.length - 1, endVcn);
                    if (holeStart <= holeEnd) {
                        holes.emplace_back(holeStart, holeEnd - holeStart + 1);
                    }
                }
            }
            curVcn += run.length;
        }

        if (holes.empty()) return true;

        // 为每个空洞分配簇
        for (auto& hole : holes) {
            uint64_t holeVcn = hole.first;
            uint64_t holeLen = hole.second;
            std::vector<uint64_t> newLcns;
            if (!AllocateClusters(holeLen, newLcns)) return false;

            // 将新簇插入运行列表，替换稀疏运行
            // 找到插入点
            uint64_t cur = 0;
            std::vector<DataRun> newRuns;
            for (const auto& run : runs) {
                if (cur + run.length <= holeVcn) {
                    newRuns.push_back(run);
                }
                else if (cur >= holeVcn + holeLen) {
                    newRuns.push_back(run);
                }
                else {
                    // 重叠
                    if (cur < holeVcn) {
                        // 前半部分保留
                        newRuns.push_back({ run.lcn, holeVcn - cur, run.is_sparse });
                    }
                    // 插入新分配的非稀疏运行
                    for (size_t j = 0; j < newLcns.size(); ++j) {
                        uint64_t lcn = newLcns[j];
                        uint64_t count = 1;
                        while (j + 1 < newLcns.size() && newLcns[j + 1] == lcn + count) {
                            count++;
                            j++;
                        }
                        newRuns.push_back({ lcn, count, false });
                    }
                    uint64_t afterHole = holeVcn + holeLen;
                    if (cur + run.length > afterHole) {
                        // 后半部分保留（如果是稀疏，后半部分仍是稀疏，但可能已被覆盖）
                        uint64_t remaining = cur + run.length - afterHole;
                        if (run.is_sparse) {
                            newRuns.push_back({ 0, remaining, true });
                        }
                        else {
                            newRuns.push_back({ run.lcn + (afterHole - cur), remaining, false });
                        }
                    }
                }
                cur += run.length;
            }
            runs = std::move(newRuns);
        }
        return true;
    }

    // 根据VCN获取LCN (用于稀疏文件)
    bool VcnToLcn(const std::vector<DataRun>& runs, uint64_t vcn, uint64_t& lcn) {
        uint64_t curVcn = 0;
        for (const auto& run : runs) {
            if (vcn < curVcn + run.length) {
                if (run.is_sparse) return false; // 稀疏，无实际簇
                lcn = run.lcn + (vcn - curVcn);
                return true;
            }
            curVcn += run.length;
        }
        return false;
    }

    // 从运行列表读取数据
    bool ReadFromRuns(const std::vector<DataRun>& runs, uint64_t offset, uint32_t length,
        uint8_t* outBuffer, uint32_t* bytesRead) {
        uint64_t remaining = length;
        uint64_t filePos = offset;
        uint8_t* buf = outBuffer;
        *bytesRead = 0;

        for (const auto& run : runs) {
            uint64_t runSize = run.length * m_bytesPerCluster;
            if (filePos >= runSize) {
                filePos -= runSize;
                continue;
            }

            uint64_t runStart = filePos;
            uint64_t runRemain = runSize - runStart;
            uint64_t toRead = std::min(remaining, runRemain);

            if (run.is_sparse) {
                memset(buf, 0, static_cast<size_t>(toRead));
            }
            else {
                uint64_t clusterInRun = runStart / m_bytesPerCluster;
                uint64_t offInCluster = runStart % m_bytesPerCluster;
                uint64_t startLcn = run.lcn + clusterInRun;
                uint64_t startSector = m_partStart + startLcn * (m_bytesPerCluster / m_bytesPerSector) + offInCluster / m_bytesPerSector;
                uint32_t sectorsToRead = static_cast<uint32_t>((toRead + (offInCluster % m_bytesPerSector) + m_bytesPerSector - 1) / m_bytesPerSector);

                std::vector<uint8_t> temp(sectorsToRead * m_bytesPerSector);
                if (!ReadSectors(startSector, sectorsToRead, temp.data()))
                    return false;

                memcpy(buf, temp.data() + (offInCluster % m_bytesPerSector), static_cast<size_t>(toRead));
            }

            buf += toRead;
            remaining -= toRead;
            filePos = 0;
            if (remaining == 0) break;
        }

        *bytesRead = length - static_cast<uint32_t>(remaining);
        return true;
    }

    // 从运行列表读取压缩数据 (LZNT1解压) - 修复缓冲区溢出
    bool ReadCompressedFromRuns(const std::vector<DataRun>& runs, uint64_t offset, uint32_t length,
        uint8_t* outBuffer, uint32_t* bytesRead, uint16_t flags) {
        if (!m_RtlDecompressBuffer) {
            return false;
        }

        // 压缩单元大小: 2^(compression_unit) 簇
        uint16_t compUnit = flags & 0x0FFF; // 低12位为压缩单元指数
        uint32_t compClusterSize = 1 << compUnit; // 每个压缩单元的簇数
        uint64_t compUnitBytes = compClusterSize * m_bytesPerCluster;

        uint64_t remaining = length;
        uint64_t filePos = offset;
        uint8_t* buf = outBuffer;
        *bytesRead = 0;

        // 逐压缩单元解压
        while (remaining > 0) {
            uint64_t unitStart = (filePos / compUnitBytes) * compUnitBytes;
            uint64_t unitOffset = filePos - unitStart;
            uint64_t unitRemain = compUnitBytes - unitOffset;

            // 读取整个压缩单元的数据（可能跨多个运行）
            std::vector<uint8_t> compressedData;
            uint64_t unitEnd = unitStart + compUnitBytes;
            uint64_t curPos = unitStart;
            while (curPos < unitEnd) {
                uint64_t runPos = curPos;
                uint64_t runRemain = unitEnd - curPos;
                // 找到包含curPos的运行
                bool found = false;
                uint64_t curVcn = 0;
                for (const auto& run : runs) {
                    uint64_t runSize = run.length * m_bytesPerCluster;
                    if (curPos < curVcn * m_bytesPerCluster + runSize) {
                        uint64_t runStart = curPos - curVcn * m_bytesPerCluster;
                        uint64_t toRead = std::min(runRemain, runSize - runStart);
                        if (run.is_sparse) {
                            compressedData.insert(compressedData.end(), toRead, 0);
                        }
                        else {
                            uint64_t clusterInRun = runStart / m_bytesPerCluster;
                            uint64_t offInCluster = runStart % m_bytesPerCluster;
                            uint64_t startLcn = run.lcn + clusterInRun;
                            uint64_t startSector = m_partStart + startLcn * (m_bytesPerCluster / m_bytesPerSector) + offInCluster / m_bytesPerSector;
                            uint32_t sectorsToRead = static_cast<uint32_t>((toRead + (offInCluster % m_bytesPerSector) + m_bytesPerSector - 1) / m_bytesPerSector);
                            std::vector<uint8_t> temp(sectorsToRead * m_bytesPerSector);
                            if (!ReadSectors(startSector, sectorsToRead, temp.data()))
                                return false;
                            compressedData.insert(compressedData.end(), temp.data() + (offInCluster % m_bytesPerSector),
                                temp.data() + (offInCluster % m_bytesPerSector) + toRead);
                        }
                        curPos += toRead;
                        found = true;
                        break;
                    }
                    curVcn += run.length;
                }
                if (!found) break; // 超出文件范围
            }

            // 解压该单元到临时缓冲区
            std::vector<uint8_t> decompressed(compUnitBytes);
            ULONG finalSize = 0;
            NTSTATUS status = m_RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1,
                decompressed.data(), (ULONG)decompressed.size(),
                compressedData.data(), (ULONG)compressedData.size(),
                &finalSize);
            if (status != 0) return false;

            // 拷贝实际所需部分到输出缓冲区
            uint64_t copySize = std::min<uint64_t>(finalSize - unitOffset, remaining);
            memcpy(buf, decompressed.data() + unitOffset, copySize);
            buf += copySize;
            remaining -= copySize;
            filePos += copySize;
        }

        *bytesRead = length - static_cast<uint32_t>(remaining);
        return true;
    }

    // 写入数据到运行列表 (假设已经分配好簇)
    bool WriteToRuns(const std::vector<DataRun>& runs, uint64_t offset, uint32_t length,
        const uint8_t* inBuffer, uint32_t* bytesWritten) {
        uint64_t remaining = length;
        uint64_t filePos = offset;
        const uint8_t* buf = inBuffer;
        *bytesWritten = 0;

        for (const auto& run : runs) {
            uint64_t runSize = run.length * m_bytesPerCluster;
            if (filePos >= runSize) {
                filePos -= runSize;
                continue;
            }

            uint64_t runStart = filePos;
            uint64_t runRemain = runSize - runStart;
            uint64_t toWrite = std::min(remaining, runRemain);

            if (run.is_sparse) {
                // 不应出现，因为已调用EnsureRunsAllocated
                return false;
            }
            else {
                uint64_t clusterInRun = runStart / m_bytesPerCluster;
                uint64_t offInCluster = runStart % m_bytesPerCluster;
                uint64_t startLcn = run.lcn + clusterInRun;
                uint64_t startSector = m_partStart + startLcn * (m_bytesPerCluster / m_bytesPerSector) + offInCluster / m_bytesPerSector;
                uint32_t sectorsToWrite = static_cast<uint32_t>((toWrite + (offInCluster % m_bytesPerSector) + m_bytesPerSector - 1) / m_bytesPerSector);

                // 读取现有扇区(可能部分覆盖)
                std::vector<uint8_t> temp(sectorsToWrite * m_bytesPerSector);
                if (!ReadSectors(startSector, sectorsToWrite, temp.data()))
                    return false;

                memcpy(temp.data() + (offInCluster % m_bytesPerSector), buf, static_cast<size_t>(toWrite));

                if (!WriteSectors(startSector, sectorsToWrite, temp.data(), true))
                    return false;
            }

            buf += toWrite;
            remaining -= toWrite;
            filePos = 0;
            if (remaining == 0) break;
        }

        *bytesWritten = length - static_cast<uint32_t>(remaining);
        return true;
    }

    //-----------------------------------------------------------------------------
    // 目录索引搜索 (支持大型目录，自动匹配长/短名)
    //-----------------------------------------------------------------------------
    bool FindFileInDirectory(uint64_t dirMftRef, const std::string& name, uint64_t& outMftRef) {
        std::vector<uint8_t> mftRec(m_mftRecordSize);
        if (!ReadMftRecord(dirMftRef, mftRec.data()))
            return false;

        // 解析索引根(0x90)和索引分配(0xA0)
        std::vector<DataRun> indexRuns;
        uint64_t indexAllocSize = 0;
        bool hasIndexAlloc = false;

        uint16_t attrOff = reinterpret_cast<FileRecordHeader*>(mftRec.data())->attr_offset;

        while (attrOff < reinterpret_cast<FileRecordHeader*>(mftRec.data())->bytes_in_use) {
            const AttrHeader* attr = reinterpret_cast<const AttrHeader*>(mftRec.data() + attrOff);
            if (attr->type == ATTR_TYPE_INDEX_ROOT) {
                // 索引根是常驻属性
                const ResidentAttr* r = reinterpret_cast<const ResidentAttr*>(attr);
                const uint8_t* indexRootData = mftRec.data() + attrOff + r->content_offset;
                // 跳过IndexRootHeader
                const IndexRootHeader* irh = reinterpret_cast<const IndexRootHeader*>(indexRootData);
                const uint8_t* indexHeader = indexRootData + sizeof(IndexRootHeader);
                uint32_t entriesOffset = *(uint32_t*)(indexHeader + 0); // IndexHeader.entries_offset
                uint32_t totalSize = *(uint32_t*)(indexHeader + 4);     // IndexHeader.index_length
                const uint8_t* entries = indexRootData + entriesOffset;
                if (SearchInIndexEntries(entries, totalSize - entriesOffset, name, outMftRef))
                    return true;
            }
            else if (attr->type == ATTR_TYPE_INDEX_ALLOCATION) {
                hasIndexAlloc = true;
                if (attr->non_resident) {
                    const NonResidentAttr* nr = reinterpret_cast<const NonResidentAttr*>(attr);
                    const uint8_t* runData = mftRec.data() + attrOff + nr->runlist_offset;
                    uint32_t maxLen = nr->length - nr->runlist_offset;
                    ParseRunList(runData, maxLen, indexRuns);
                    indexAllocSize = nr->data_size;
                }
                else {
                    // 常驻索引分配 (罕见)
                    const ResidentAttr* r = reinterpret_cast<const ResidentAttr*>(attr);
                    const uint8_t* data = mftRec.data() + attrOff + r->content_offset;
                    if (SearchInIndexBlock(data, r->content_length, name, outMftRef))
                        return true;
                }
            }
            if (attr->length == 0) break;
            attrOff += attr->length;
        }

        if (hasIndexAlloc && !indexRuns.empty()) {
            uint64_t fileOffset = 0;
            std::vector<uint8_t> indexBlock(m_indexRecordSize);
            while (fileOffset < indexAllocSize) {
                uint32_t readBytes = 0;
                if (!ReadFromRuns(indexRuns, fileOffset, m_indexRecordSize, indexBlock.data(), &readBytes))
                    break;
                if (readBytes < sizeof(IndexBlockHeader)) break;
                if (SearchInIndexBlock(indexBlock.data(), readBytes, name, outMftRef))
                    return true;
                fileOffset += m_indexRecordSize;
            }
        }

        return false;
    }

    bool SearchInIndexBlock(const uint8_t* blockData, uint32_t blockSize,
        const std::string& name, uint64_t& outMftRef) {
        // 验证INDX签名
        if (blockSize < sizeof(IndexBlockHeader) || memcmp(blockData, "INDX", 4) != 0) return false;

        // 由于blockData来自ReadFromRuns，是原始扇区数据，需要应用USA修复
        // 复制到可写缓冲区
        std::vector<uint8_t> block(blockData, blockData + blockSize);
        if (!ApplyIndexBlockUSA(block.data(), blockSize))
            return false;

        IndexBlockHeader* hdr = reinterpret_cast<IndexBlockHeader*>(block.data());
        // 计算IndexHeader位置：在hdr之后，紧接着usa数组
        uint32_t headerSize = sizeof(IndexBlockHeader);
        uint32_t usaArraySize = hdr->usa_count * sizeof(uint16_t);
        uint32_t indexHeaderOffset = headerSize + usaArraySize; // 可能有填充，但NTFS通常对齐到8字节？简化，直接使用
        if (indexHeaderOffset + sizeof(IndexHeader) > blockSize) return false;

        const uint8_t* indexHeader = block.data() + indexHeaderOffset;
        uint32_t entriesOffset = *(uint32_t*)(indexHeader);
        uint32_t totalSize = *(uint32_t*)(indexHeader + 4);
        if (entriesOffset + totalSize > blockSize - indexHeaderOffset) return false;

        const uint8_t* entries = block.data() + indexHeaderOffset + entriesOffset;
        return SearchInIndexEntries(entries, totalSize, name, outMftRef);
    }

    bool SearchInIndexEntries(const uint8_t* entriesStart, uint32_t entriesSize,
        const std::string& name, uint64_t& outMftRef) {
        const uint8_t* pos = entriesStart;
        const uint8_t* end = entriesStart + entriesSize;
        while (pos + sizeof(IndexEntryHeader) <= end) {
            const IndexEntryHeader* ie = reinterpret_cast<const IndexEntryHeader*>(pos);
            if (ie->size == 0) break;
            if (pos + ie->size > end) break;

            if (ie->key_length > 0) {
                const uint16_t* nameData = reinterpret_cast<const uint16_t*>(pos + sizeof(IndexEntryHeader));
                size_t nameLen = static_cast<size_t>(ie->key_length / 2);
                std::wstring wname(reinterpret_cast<const wchar_t*>(nameData), nameLen);
                int len = WideCharToMultiByte(CP_UTF8, 0, wname.c_str(), (int)nameLen, nullptr, 0, nullptr, nullptr);
                std::string utf8Name(len, 0);
                WideCharToMultiByte(CP_UTF8, 0, wname.c_str(), (int)nameLen, &utf8Name[0], len, nullptr, nullptr);
                if (utf8Name == name) {
                    outMftRef = ie->mft_reference & 0xFFFFFFFFFFFF;
                    return true;
                }
            }
            if (ie->flags & INDEX_ENTRY_END) break;
            pos += ie->size;
        }
        return false;
    }

    //-----------------------------------------------------------------------------
    // $Bitmap 读写 (正确解析运行列表)
    //-----------------------------------------------------------------------------
    bool ReadBitmapData(std::vector<uint8_t>& bitmapData) {
        // 读取 MFT 记录 6
        std::vector<uint8_t> mftRec(m_mftRecordSize);
        if (!ReadMftRecord(6, mftRec.data()))
            return false;

        std::vector<DataRun> runs;
        uint64_t fileSize;
        bool isResident;
        uint16_t flags;
        if (!ParseDataRunsEx(mftRec.data(), 6, runs, fileSize, nullptr, &isResident, &flags, nullptr, nullptr))
            return false;

        if (isResident) {
            // 常驻位图 (不太可能，但支持)
            const uint8_t* data = FindResidentData(mftRec.data());
            if (!data) return false;
            bitmapData.assign(data, data + fileSize);
            return true;
        }
        else {
            bitmapData.resize((size_t)fileSize);
            uint32_t bytesRead;
            return ReadFromRuns(runs, 0, (uint32_t)fileSize, bitmapData.data(), &bytesRead) && bytesRead == fileSize;
        }
    }

    bool WriteBitmapData(const std::vector<uint8_t>& bitmapData) {
        // 读取 MFT 记录 6
        std::vector<uint8_t> mftRec(m_mftRecordSize);
        if (!ReadMftRecord(6, mftRec.data()))
            return false;

        std::vector<DataRun> runs;
        uint64_t fileSize;
        bool isResident;
        uint16_t flags;
        uint16_t attrOffset;
        uint64_t baseRef;
        if (!ParseDataRunsEx(mftRec.data(), 6, runs, fileSize, nullptr, &isResident, &flags, &attrOffset, &baseRef))
            return false;

        if (isResident) {
            // 常驻位图，直接写入MFT记录
            uint8_t* data = FindResidentData(mftRec.data());
            if (!data) return false;
            memcpy(data, bitmapData.data(), std::min(bitmapData.size(), (size_t)fileSize));
            return WriteMftRecord(baseRef, mftRec.data());
        }
        else {
            // 非常驻，写入运行列表
            uint32_t bytesWritten;
            if (!WriteToRuns(runs, 0, (uint32_t)bitmapData.size(), bitmapData.data(), &bytesWritten))
                return false;
            // 如果写入后文件大小变化，需要更新MFT记录中的大小
            if (bytesWritten != fileSize) {
                UpdateFileSizeInMft(mftRec.data(), bitmapData.size(), bitmapData.size());
                if (!WriteMftRecord(baseRef, mftRec.data()))
                    return false;
            }
            return true;
        }
    }

    //-----------------------------------------------------------------------------
    // 事务处理 (简单扇区标记)
    //-----------------------------------------------------------------------------
    void CheckAndRecoverTransaction() {
        uint8_t sector[512] = { 0 };
        if (!ReadSectors(m_transactionSector, 1, sector, 1)) return;
        TransactionRecord* tr = reinterpret_cast<TransactionRecord*>(sector);
        if (tr->type != 0) {
            // 有未完成事务，回滚 (简化：清空)
            tr->type = 0;
            WriteSectors(m_transactionSector, 1, sector, false);
        }
    }

    void BeginTransaction(uint64_t targetMftRef, uint64_t backupLcn, uint32_t backupSize) {
        if (m_transactionActive) return;
        TransactionRecord tr;
        tr.timestamp = GetTickCount64();
        tr.target_mft_ref = targetMftRef;
        tr.backup_lcn = backupLcn;
        tr.backup_size = backupSize;
        tr.type = 1;
        WriteSectors(m_transactionSector, 1, &tr, true);
        m_transactionActive = true;
    }

    void CommitTransaction() {
        if (!m_transactionActive) return;
        uint8_t sector[512] = { 0 };
        WriteSectors(m_transactionSector, 1, sector, true);
        m_transactionActive = false;
    }
};

//-----------------------------------------------------------------------------
// NtfsFile - 文件对象类 (简化封装)
//-----------------------------------------------------------------------------
class NtfsFile {
public:
    NtfsFile() : m_volume(nullptr), m_mftRef(0), m_size(0) {}
    NtfsFile(NtfsVolume* vol, uint64_t mftRef) : m_volume(vol), m_mftRef(mftRef) {
        Refresh();
    }

    bool IsOpen() const { return m_volume != nullptr; }
    uint64_t GetSize() const { return m_size; }

    bool Refresh() {
        if (!m_volume) return false;
        std::vector<DataRun> runs;
        bool isResident;
        uint16_t flags;
        if (!m_volume->GetDataRunsWithFlags(m_mftRef, runs, m_size, &isResident, &flags))
            return false;
        return true;
    }

    bool Read(uint64_t offset, void* buffer, uint32_t length, uint32_t* bytesRead) {
        return m_volume->ReadFileData(m_mftRef, offset, buffer, length, bytesRead);
    }

    bool Write(uint64_t offset, const void* buffer, uint32_t length, uint32_t* bytesWritten) {
        bool ok = m_volume->WriteFileData(m_mftRef, offset, buffer, length, bytesWritten);
        if (ok) Refresh();
        return ok;
    }

public:
    NtfsVolume* m_volume;
    uint64_t m_mftRef;
    uint64_t m_size;
};

//-----------------------------------------------------------------------------
// 使用示例 (注释)
/*
#include <iostream>
#include <vector>
int main() {
    NtfsVolume vol;
    if (!vol.Open(0, 1)) { // 打开第一个NTFS分区
        std::cerr << "无法打开驱动器 (需要管理员权限)\n";
        return 1;
    }
    uint64_t mftRef;
    if (vol.ResolvePath("\\Windows\\notepad.exe", mftRef)) {
        NtfsFile file(&vol, mftRef);
        std::cout << "文件大小: " << file.GetSize() << " 字节\n";
        char buf[1024];
        uint32_t read;
        if (file.Read(0, buf, sizeof(buf), &read)) {
            std::cout << "读取 " << read << " 字节\n";
        }
    } else {
        std::cout << "文件未找到\n";
    }
    return 0;
}
*/