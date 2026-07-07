#include "CommonDefs.h"
#include "GarbageCleaner.h"
#include "signature_protection_nocert.h"
#include <thread>
#include <queue>
#include <iomanip>
#include <shlobj.h>
#include <shellapi.h>

// extern declarations for functions used by GarbageCleaner
extern bool IsInUnifiedWhitelist(const std::wstring& processName);

// ============================================================================
// GarbageCleaner — 系统垃圾文件扫描与清理 方法实现
// ============================================================================

std::vector<GarbageCleaner::ScanTarget> GarbageCleaner::GetScanTargets() {
    wchar_t userProfile[MAX_PATH] = L"C:\\Users\\Default";
    wchar_t localAppData[MAX_PATH] = L"";
    wchar_t appData[MAX_PATH] = L"";
    wchar_t tempPath[MAX_PATH] = L"C:\\Windows\\Temp";

    GetEnvironmentVariableW(L"USERPROFILE", userProfile, MAX_PATH);
    GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH);
    GetEnvironmentVariableW(L"APPDATA", appData, MAX_PATH);
    GetTempPathW(MAX_PATH, tempPath);

    std::vector<ScanTarget> targets;

    if (tempPath[0] != L'\0') {
        targets.push_back({tempPath, L"系统临时文件", L"Windows临时文件夹", {L".tmp", L".temp", L"~"}, true, 3});
    }
    targets.push_back({L"C:\\Windows\\Temp", L"Windows临时文件", L"Windows系统临时文件夹", {L".tmp", L".temp"}, true, 2});
    if (localAppData[0] != L'\0') {
        targets.push_back({std::wstring(localAppData) + L"\\Temp", L"用户临时文件", L"用户临时文件夹", {L".tmp", L".temp"}, true, 3});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Windows\\INetCache", L"浏览器缓存", L"Internet临时缓存", {L"*"}, true, 5});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Windows\\IEDownloads", L"浏览器下载", L"IE下载文件夹", {L"*"}, true, 1});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Edge\\User Data\\Default\\Cache", L"Edge缓存", L"Edge浏览器缓存", {L"*"}, true, 3});
        targets.push_back({std::wstring(localAppData) + L"\\Google\\Chrome\\User Data\\Default\\Cache", L"Chrome缓存", L"Chrome浏览器缓存", {L"*"}, true, 3});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Windows\\Explorer", L"缩略图缓存", L"Windows缩略图缓存", {L"thumbcache_*.db"}, false, 1});
        targets.push_back({std::wstring(localAppData) + L"\\CrashDumps", L"崩溃转储", L"程序崩溃转储文件", {L"*.dmp"}, false, 1});
        targets.push_back({std::wstring(localAppData) + L"\\D3DSCache", L"DirectX缓存", L"Direct3D着色器缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Packages", L"UWP缓存", L"UWP应用缓存", {L"*"}, true, 2});
    }
    if (appData[0] != L'\0') {
        targets.push_back({std::wstring(appData) + L"\\Microsoft\\Windows\\Recent", L"最近使用记录", L"最近打开文件记录", {L"*"}, false, 1});
    }
    if (userProfile[0] != L'\0') {
        targets.push_back({std::wstring(userProfile) + L"\\Downloads", L"下载文件夹旧文件", L"下载文件夹中的临时文件", {L".tmp", L".temp", L".partial"}, false, 1});
    }
    targets.push_back({L"C:\\Windows\\Prefetch", L"预读取文件", L"Windows预读取文件", {L"*.pf"}, false, 1});
    targets.push_back({L"C:\\Windows\\Logs", L"系统日志", L"Windows日志文件", {L"*.log", L"*.etl"}, true, 3});
    targets.push_back({L"C:\\$WinREAgent", L"WinRE缓存", L"Windows恢复环境缓存", {L"*"}, true, 2});

    wchar_t commonAppData[MAX_PATH] = L"";
    GetEnvironmentVariableW(L"ALLUSERSPROFILE", commonAppData, MAX_PATH);
    if (commonAppData[0] != L'\0') {
        targets.push_back({std::wstring(commonAppData) + L"\\Microsoft\\Windows\\WER", L"错误报告", L"Windows错误报告", {L"*"}, true, 2});
    }
    targets.push_back({L"C:\\inetpub\\logs\\LogFiles", L"IIS日志", L"Internet Information Services日志", {L"*"}, true, 3});
    if (localAppData[0] != L'\0') {
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Edge\\User Data\\Default\\Code Cache", L"Edge代码缓存", L"Edge浏览器代码缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Edge\\User Data\\Default\\GPUCache", L"Edge GPU缓存", L"Edge浏览器GPU缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Edge\\User Data\\ShaderCache", L"Edge着色器缓存", L"Edge浏览器着色器缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Edge\\Application\\Cache", L"Edge应用缓存", L"Edge应用程序缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\EdgeUpdate", L"Edge更新缓存", L"Edge浏览器更新缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Windows\\INetCookies", L"Cookie缓存", L"Internet Cookie缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Windows\\ActionCenterCache", L"操作中心缓存", L"Windows操作中心缓存", {L"*"}, true, 1});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Windows\\Themes\\CachedImages", L"主题缓存", L"Windows主题缓存图片", {L"*"}, true, 1});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Windows\\Notifications", L"通知缓存", L"Windows通知缓存", {L"*"}, true, 1});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Windows\\Activity", L"活动历史记录", L"Windows活动时间线历史", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Windows\\History", L"Edge历史记录", L"Edge浏览器访问历史", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Windows\\WebCache", L"WebCache数据库", L"Internet Explorer WebCache数据库", {L"*.dat"}, false, 1});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Windows\\RetailDemo", L"零售演示内容", L"Windows零售演示内容缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Windows\\GameTrayIcons", L"游戏图标缓存", L"Windows游戏栏图标缓存", {L"*"}, true, 1});
    }
    if (appData[0] != L'\0') {
        targets.push_back({std::wstring(appData) + L"\\Microsoft\\Windows\\Cookies", L"Cookie文件", L"浏览器Cookie", {L"*"}, false, 1});
        targets.push_back({std::wstring(appData) + L"\\Microsoft\\Windows\\Recent\\AutomaticDestinations", L"跳转列表缓存", L"任务栏跳转列表自动跳转缓存", {L"*"}, false, 1});
        targets.push_back({std::wstring(appData) + L"\\Microsoft\\Windows\\Recent\\CustomDestinations", L"跳转列表缓存", L"任务栏跳转列表自定义跳转缓存", {L"*"}, false, 1});
    }
    targets.push_back({L"C:\\Windows\\System32\\LogFiles", L"系统日志文件", L"Windows系统日志文件", {L"*"}, true, 2});
    targets.push_back({L"C:\\Windows\\Panther", L"安装日志", L"Windows安装日志", {L"*.log", L"*.xml"}, true, 2});
    targets.push_back({L"C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Windows\\DFS", L"DFS缓存", L"分布式文件系统缓存", {L"*"}, true, 2});
    targets.push_back({L"C:\\Windows\\System32\\winevt\\Logs", L"事件日志备份", L"Windows事件日志备份文件", {L"*.evtx"}, false, 1});
    targets.push_back({L"C:\\Windows\\Downloaded Program Files", L"已下载程序文件", L"Windows已下载的程序文件", {L"*"}, false, 1});
    targets.push_back({L"C:\\Windows\\SoftwareDistribution\\Download", L"Windows更新缓存", L"Windows更新下载缓存", {L"*"}, true, 3});
    targets.push_back({L"C:\\Windows\\WinSxS\\Backup", L"WinSxS备份", L"Windows组件备份", {L"*"}, false, 1});
    // 注意: WinSxS主目录绝对不能清理！仅清理其下的Temp子目录(真正的临时文件)
    targets.push_back({L"C:\\Windows\\WinSxS\\Temp", L"WinSxS临时文件", L"WinSxS组件存储临时目录(非组件本身)", {L"*"}, false, 1});
    targets.push_back({L"C:\\Windows\\Panther\\UnattendGC", L"应答文件缓存", L"Windows安装应答文件", {L"*"}, false, 1});
    targets.push_back({L"C:\\Windows\\System32\\CodeStore", L"代码存储缓存", L"Windows代码存储缓存", {L"*"}, false, 1});
    targets.push_back({L"C:\\Windows\\System32\\catroot2", L"签名缓存", L"Windows证书签名缓存", {L"*"}, true, 1});
    targets.push_back({L"C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Temp", L"系统临时文件", L"系统用户临时文件夹", {L"*"}, true, 3});

    if (localAppData[0] != L'\0') {
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Edge\\User Data\\Default\\Network\\Cache", L"Edge网络缓存", L"Edge浏览器网络缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Edge\\User Data\\Default\\Sessions", L"Edge会话缓存", L"Edge浏览器会话数据", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Edge\\User Data\\Default\\Session Storage", L"Edge会话存储", L"Edge浏览器会话存储", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Google\\Chrome\\User Data\\Default\\Code Cache", L"Chrome代码缓存", L"Chrome浏览器代码缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Google\\Chrome\\User Data\\Default\\GPUCache", L"Chrome GPU缓存", L"Chrome浏览器GPU缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Google\\Chrome\\User Data\\Default\\ShaderCache", L"Chrome着色器缓存", L"Chrome浏览器着色器缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Google\\Chrome\\User Data\\Default\\Session Storage", L"Chrome会话存储", L"Chrome浏览器会话存储", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Edge\\User Data\\Default\\Local Storage", L"Chrome本地存储", L"Chrome浏览器本地存储", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Google\\Chrome\\User Data\\Default\\ShaderCache", L"Chrome全局着色器", L"Chrome浏览器着色器缓存", {L"*"}, true, 2});
        // Edge/Chrome 深层Web应用缓存(网页应用/PWA数据，可占数GB)
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Edge\\User Data\\Default\\blob_storage", L"Edge Blob存储", L"Edge浏览器二进制大对象存储(PWA/网页应用)", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Edge\\User Data\\Default\\Service Worker\\CacheStorage", L"Edge SW缓存", L"Edge Service Worker缓存存储(PWA离线数据)", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Edge\\User Data\\Default\\databases", L"Edge Web数据库", L"Edge浏览器Web数据库(IndexedDB/WebSQL)", {L"*"}, false, 1});
        targets.push_back({std::wstring(localAppData) + L"\\Google\\Chrome\\User Data\\Default\\blob_storage", L"Chrome Blob存储", L"Chrome浏览器二进制大对象存储(PWA/网页应用)", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Google\\Chrome\\User Data\\Default\\Service Worker\\CacheStorage", L"Chrome SW缓存", L"Chrome Service Worker缓存存储(PWA离线数据)", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Google\\Chrome\\User Data\\Default\\databases", L"Chrome Web数据库", L"Chrome浏览器Web数据库(IndexedDB/WebSQL)", {L"*"}, false, 1});
        targets.push_back({std::wstring(localAppData) + L"\\Mozilla\\Firefox\\Profiles", L"Firefox缓存(仅缓存)", L"Mozilla Firefox浏览器缓存(保留书签/密码/偏好设置)", {L"cache*", L"*.cache", L"*.cache2", L"*.tmp", L"telemetry*", L"healthreport"}, true, 3});
        targets.push_back({std::wstring(localAppData) + L"\\Opera Software\\Opera Stable\\Cache", L"Opera缓存", L"Opera浏览器缓存", {L"*"}, true, 3});
        targets.push_back({std::wstring(localAppData) + L"\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Cache", L"Brave缓存", L"Brave浏览器缓存", {L"*"}, true, 3});
        targets.push_back({std::wstring(localAppData) + L"\\Vivaldi\\User Data\\Default\\Cache", L"Vivaldi缓存", L"Vivaldi浏览器缓存", {L"*"}, true, 3});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Windows\\Explorer\\IconCacheToDelete", L"图标缓存删除", L"待删除的图标缓存", {L"*"}, false, 1});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\InputPersonalization", L"输入学习数据", L"微软输入学习数据", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\InputPersonalization\\Textures", L"输入纹理缓存", L"微软输入纹理缓存", {L"*"}, true, 1});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Windows\\Feedback\\Da", L"反馈数据", L"Windows反馈数据", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Windows\\SettingSync", L"设置同步缓存", L"Windows设置同步缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Windows\\Explorer\\Amcache", L"Amcache缓存", L"程序兼容客户端缓存", {L"Amcache.hve"}, false, 1});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Windows\\Explorer\\ThumbnailsToDelete", L"缩略图删除", L"待删除的缩略图", {L"*"}, false, 1});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Windows\\Temporary Internet Files", L"IE临时文件", L"Internet Explorer临时文件", {L"*"}, true, 3});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Windows\\INetCache\\Content.IE5", L"IE5缓存", L"Internet Explorer 5缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Windows\\INetCache\\Content.IE6", L"IE6缓存", L"Internet Explorer 6缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Windows\\INetCache\\Content.IE7", L"IE7缓存", L"Internet Explorer 7缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Windows\\INetCache\\Content.IE8", L"IE8缓存", L"Internet Explorer 8缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Windows\\WER\\ReportArchive", L"错误报告归档", L"Windows错误报告归档", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Windows\\WER\\ReportQueue", L"错误报告队列", L"Windows错误报告队列", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Windows\\TAP", L"TAP驱动缓存", L"TAP网络驱动缓存", {L"*"}, true, 1});
    }
    if (appData[0] != L'\0') {
        targets.push_back({std::wstring(appData) + L"\\Microsoft\\Windows\\Explorer\\", L"跳转列表", L"任务栏跳转列表", {L"*"}, false, 1});
        targets.push_back({std::wstring(appData) + L"\\Microsoft\\Windows\\Notifications\\PlatStore", L"通知存储", L"Windows通知存储", {L"*"}, false, 1});
    }
    if (userProfile[0] != L'\0') {
        targets.push_back({std::wstring(userProfile) + L"\\AppData\\Local\\Spotify\\Data", L"Spotify缓存(仅临时)", L"Spotify音乐临时缓存(保留离线音乐/登录状态)", {L"*.cache", L"*.tmp", L"*.log"}, false, 1});
        targets.push_back({std::wstring(userProfile) + L"\\AppData\\Local\\Discord\\Cache", L"Discord缓存", L"Discord缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(userProfile) + L"\\AppData\\Local\\Discord\\Code Cache", L"Discord代码缓存", L"Discord代码缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(userProfile) + L"\\AppData\\Local\\Discord\\GPUCache", L"Discord GPU缓存", L"Discord GPU缓存", {L"*"}, true, 1});
        targets.push_back({std::wstring(userProfile) + L"\\AppData\\Local\\Discord\\databases", L"Discord数据库缓存", L"Discord数据库缓存(可重建)", {L"*.db", L"*.db-journal", L"*.db-wal"}, false, 1});
        targets.push_back({std::wstring(userProfile) + L"\\AppData\\Local\\Slack\\Cache", L"Slack缓存", L"Slack缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(userProfile) + L"\\AppData\\Local\\Slack\\Code Cache", L"Slack代码缓存", L"Slack代码缓存", {L"*"}, true, 1});
        targets.push_back({std::wstring(userProfile) + L"\\AppData\\Local\\Slack\\GPUCache", L"Slack GPU缓存", L"Slack GPU缓存", {L"*"}, true, 1});
        targets.push_back({std::wstring(userProfile) + L"\\AppData\\Local\\Slack\\databases", L"Slack数据库缓存", L"Slack数据库缓存(可重建)", {L"*.db", L"*.db-journal"}, false, 1});
        targets.push_back({std::wstring(userProfile) + L"\\AppData\\Local\\Teams\\Cache", L"Teams缓存", L"Microsoft Teams缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(userProfile) + L"\\AppData\\Local\\Teams\\Code Cache", L"Teams代码缓存", L"Microsoft Teams代码缓存", {L"*"}, true, 1});
        targets.push_back({std::wstring(userProfile) + L"\\AppData\\Local\\Teams\\GPUCache", L"Teams GPU缓存", L"Microsoft Teams GPU缓存", {L"*"}, true, 1});
        targets.push_back({std::wstring(userProfile) + L"\\AppData\\Local\\Teams\\blob_storage", L"Teams Blob存储", L"Microsoft Teams Blob数据存储(会议录制缩略图等)", {L"*"}, true, 1});
        targets.push_back({std::wstring(userProfile) + L"\\AppData\\Local\\Teams\\databases", L"Teams数据库缓存", L"Microsoft Teams数据库(可重建)", {L"*.db", L"*.db-journal"}, false, 1});
        targets.push_back({std::wstring(userProfile) + L"\\AppData\\Local\\Teams\\tmp", L"Teams临时文件", L"Microsoft Teams临时文件", {L"*"}, false, 1});
        targets.push_back({std::wstring(userProfile) + L"\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Cache", L"Brave用户缓存", L"Brave浏览器用户缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(userProfile) + L"\\AppData\\Local\\Vivaldi\\User Data\\Default\\Cache", L"Vivaldi用户缓存", L"Vivaldi浏览器用户缓存", {L"*"}, true, 2});
    }

    targets.push_back({L"C:\\PerfLogs\\Support", L"性能日志", L"Windows性能日志", {L"*"}, true, 2});
    targets.push_back({L"C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp", L"程序数据错误报告", L"程序数据临时错误报告", {L"*"}, true, 2});
    targets.push_back({L"C:\\ProgramData\\Microsoft\\Windows\\WER\\Archive", L"错误报告归档", L"程序数据错误报告归档", {L"*"}, true, 2});

    // ====== 系统升级残留 ======
    // 注意: $WINDOWS.~BT 和 Windows.old 不在此清理，需用户手动通过磁盘清理工具删除
    // 原因: 含系统回滚关键文件，误删可能导致无法回退或数据丢失
    targets.push_back({L"C:\\$WINDOWS.~LS", L"Win升级日志", L"Windows系统升级安装日志", {L"*.log", L"*.xml"}, true, 2});
    targets.push_back({L"C:\\Windows\\SoftwareDistribution\\DataStore", L"更新数据存储", L"Windows更新数据存储库", {L"*.log", L"*.edb"}, true, 2});
    targets.push_back({L"C:\\Windows\\SoftwareDistribution\\PostRebootEventCache.V2", L"重启事件缓存", L"Windows更新重启后事件缓存(可自动重建)", {L"*"}, false, 1});

    // ====== GPU驱动缓存 ======
    // 注意: GPU着色器缓存不清理，重建会导致游戏/应用首次启动严重卡顿(Shader Compilation Stutter)
    // 如确需清理，请使用GPU驱动控制面板中的"清除着色器缓存"功能

    // ====== Adobe系列 ======
    if (localAppData[0] != L'\0') {
        targets.push_back({std::wstring(localAppData) + L"\\Adobe\\Acrobat", L"Acrobat缓存", L"Adobe Acrobat临时缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Adobe\\CameraRaw", L"Camera Raw缓存", L"Adobe Camera Raw处理缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Adobe\\Headlights", L"Headlights缓存", L"Adobe Headlights缓存", {L"*"}, true, 1});
        targets.push_back({std::wstring(localAppData) + L"\\Adobe\\Common\\Media Cache Files", L"Adobe媒体缓存", L"Adobe通用媒体缓存文件(仅临时文件)", {L"*.pek", L"*.cfa", L"*.idx", L".mxf.*"}, true, 3});
        targets.push_back({std::wstring(localAppData) + L"\\Adobe\\Logs", L"Adobe日志", L"Adobe产品运行日志", {L"*.log"}, true, 1});
    }
    if (appData[0] != L'\0') {
        targets.push_back({std::wstring(appData) + L"\\Adobe\\Common\\Media Cache Files", L"Adobe漫游媒体缓存", L"Adobe漫游配置媒体缓存(仅临时)", {L"*.pek", L"*.cfa", L"*.idx"}, true, 2});
    }
    targets.push_back({L"C:\\ProgramFiles(x86)\\Common Files\\Adobe\\Log", L"Adobe公共日志", L"Adobe公共组件日志", {L"*"}, true, 1});

    // ====== Microsoft Office系列 ======
    if (localAppData[0] != L'\0') {
        // Office Click-to-Run文档缓存(邮件附件自动下载、共享文档缓存)
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Office\\16.0\\OfficeFileCache", L"Office文档缓存", L"Microsoft Office文档自动缓存(邮件附件等)", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\Office\\16.0\\WebServiceCache", L"Office Web缓存", L"Office Web服务缓存", {L"*"}, true, 1});
    }

    // ====== 游戏平台/通讯软件 ======
    if (localAppData[0] != L'\0') {
        // Steam
        targets.push_back({std::wstring(localAppData) + L"\\Steam\\htmlcache", L"Steam网页缓存", L"Steam内置浏览器缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Steam\\appcache", L"Steam应用缓存", L"Steam应用资源缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Steam\\logs", L"Steam日志", L"Steam客户端日志", {L"*.log", L"*.txt"}, true, 1});
        // Epic Games
        targets.push_back({std::wstring(localAppData) + L"\\EpicGamesLauncher\\Saved\\Logs", L"Epic日志", L"Epic Games启动器日志", {L"*.log"}, true, 1});
        targets.push_back({std::wstring(localAppData) + L"\\EpicGamesLauncher\\Saved\\Intermediate", L"Epic中间文件(日志)", L"Epic Games中间编译产物(仅日志，保留着色器缓存)", {L"*.log", L"*.tmp"}, false, 1});
        // Ubisoft Connect
        targets.push_back({std::wstring(localAppData) + L"\\Ubisoft Game Launcher\\cache", L"Ubisoft缓存", L"育碧启动器缓存", {L"*"}, true, 2});
        // Origin/EA
        targets.push_back({std::wstring(localAppData) + L"\\Origin\\Logs", L"Origin日志", L"EA Origin平台日志", {L"*.log"}, true, 1});
        targets.push_back({std::wstring(localAppData) + L"\\Origin\\DownloadCache", L"Origin下载缓存", L"EA Origin游戏安装包分片缓存(已装游戏不受影响)", {L"*"}, false, 1});
        // EA App(新EA桌面客户端，替代Origin)
        targets.push_back({std::wstring(localAppData) + L"\\Electronic Arts\\EA Desktop\\Logs", L"EA App日志", L"EA Desktop新客户端日志", {L"*.log"}, true, 1});
        targets.push_back({std::wstring(localAppData) + L"\\Electronic Arts\\EA Desktop\\Cache", L"EA App缓存", L"EA Desktop客户端缓存", {L"*"}, true, 2});
        // Battle.net
        targets.push_back({std::wstring(localAppData) + L"\\Battle.net\\Cache", L"战网缓存", L"暴雪战网平台缓存", {L"*"}, true, 2});
        // Riot Games(Valorant/LoL/瓦罗兰特/英雄联盟)
        targets.push_back({std::wstring(localAppData) + L"\\Riot Games", L"Riot Games缓存", L"拳头游戏客户端缓存(日志/临时文件)", {L"*.log", L"*.tmp", L"*.cache"}, true, 2});
        // QQ
        // 注意: FileRecv(接收文件)不清理，用户文件可能仍在使用
        targets.push_back({std::wstring(localAppData) + L"\\Tencent\\QQ\\Temp", L"QQ临时文件", L"QQ临时文件目录", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Tencent\\QQ\\Image", L"QQ图片缓存", L"QQ聊天图片缓存", {L"*.jpg", L"*.png", L"*.gif", L"*.webp"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Tencent\\QQ\\Video", L"QQ视频缓存", L"QQ短视频缓存", {L"*"}, true, 2});
        // 微信
        targets.push_back({std::wstring(localAppData) + L"\\Tencent\\WeChat\\FileStorage\\Temp", L"微信临时文件", L"微信临时文件存储", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Tencent\\WeChat\\Xlog", L"微信日志", L"微信运行日志", {L"*.xlog"}, true, 1});
        targets.push_back({std::wstring(appData) + L"\\Tencent\\WeChat\\Xweb", L"微信Web缓存", L"微信内置浏览器缓存", {L"*"}, true, 2});
        // 钉钉
        targets.push_back({std::wstring(localAppData) + L"\\DingTalk\\Cache", L"钉钉缓存", L"钉钉应用缓存", {L"*"}, true, 2});
        // 飞书
        targets.push_back({std::wstring(localAppData) + L"\\Feishu", L"飞书缓存", L"飞书(Lark)应用缓存", {L"*"}, true, 2});
        // 企业微信(WeCom/WeWork)
        targets.push_back({std::wstring(localAppData) + L"\\WeWork\\User\\*\\Profiles\\Cache", L"企业微信缓存", L"企业微信文件缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(appData) + L"\\WeWork\\User\\*\\Profiles\\Xlog", L"企业微信日志", L"企业微信运行日志", {L"*.xlog"}, true, 1});
        // TIM(QQ办公版)
        targets.push_back({std::wstring(localAppData) + L"\\Tencent\\TIM\\Temp", L"TIM临时文件", L"TIM临时文件目录", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Tencent\\TIM\\Image", L"TIM图片缓存", L"TIM聊天图片缓存", {L"*.jpg", L"*.png", L"*.gif", L"*.webp"}, true, 2});
        // 百度网盘 - 仅清理临时文件，不清理实际下载的文件
        targets.push_back({std::wstring(localAppData) + L"\\baidunetdisk\\download", L"百度网盘缓存(临时项)", L"百度网盘下载临时文件(保留已下载文件)", {L"*.tmp", L"*.part"}, false, 1});
        // OneDrive
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\OneDrive\\temp", L"OneDrive临时文件", L"OneDrive同步临时文件", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\OneDrive\\settings", L"OneDrive设置临时", L"OneDrive设置目录(仅临时文件，保留配置)", {L"*.tmp", L"*.old", L"*.bak"}, false, 1});
    }

    // ====== 开发工具缓存 ======
    if (localAppData[0] != L'\0') {
        // VS Code
        targets.push_back({std::wstring(localAppData) + L"\\.vscode\\CachedData", L"VSCode缓存", L"VS Code编辑器缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\.vscode\\CachedExtensionVSIXs", L"VSCode扩展缓存", L"VS Code扩展包缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\.vscode\\User\\workspaceStorage", L"VSCode工作区状态", L"VS Code工作区布局状态(非关键，删除后恢复默认)", {L"*"}, false, 1});
        targets.push_back({std::wstring(localAppData) + L"\\.vscode\\User\\History", L"VSCode本地历史", L"VS Code编辑器本地历史记录(含文件备份版本)", {L"*"}, false, 1});
        targets.push_back({std::wstring(localAppData) + L"\\.vscode\\User\\globalStorage", L"VSCode扩展全局数据", L"VS Code扩展全局存储(可能含扩展重要配置)", {L"*.log", L"*.tmp"}, false, 1});
        targets.push_back({std::wstring(localAppData) + L"\\.vscode\\CrashReporter", L"VSCode崩溃报告", L"VS Code崩溃转储", {L"*.dmp"}, false, 1});
        // Node.js/npm - 仅清理损坏/过期的缓存条目，保留有效包
        targets.push_back({std::wstring(localAppData) + L"\\npm-cache", L"npm缓存(损坏项)", L"Node.js npm缓存中损坏的文件", {L"*.tmp", L"*.lock", L".*~"}, false, 1});
        targets.push_back({std::wstring(localAppData) + L"\\Yarn", L"Yarn缓存(损坏项)", L"Yarn缓存中损坏的文件", {L"*.tmp", L"*.lock"}, false, 1});
        targets.push_back({std::wstring(localAppData) + L"\\pnpm-cache", L"pnpm缓存(损坏项)", L"pnpm缓存中损坏的文件", {L"*.tmp"}, false, 1});
        // Python pip - 仅清理临时文件和锁
        targets.push_back({std::wstring(localAppData) + L"\\pip\\cache", L"Pip缓存(临时项)", L"Python pip缓存中的临时文件", {L"*.tmp", L"*.lock"}, false, 1});
        // NuGet - 仅清理HTTP缓存和临时文件
        targets.push_back({std::wstring(localAppData) + L"\\NuGet\\http-cache", L"NuGet HTTP缓存", L".NET NuGet HTTP响应缓存", {L"*"}, true, 2});
        // Maven
        targets.push_back({std::wstring(userProfile) + L"\\.m2\\repository", L"Maven本地仓库(失败记录)", L"Java Maven依赖下载失败记录(可重新解析)", {L"*.jar.lastUpdated", L"*.lastUpdated"}, false, 1});
        // Gradle - 仅清理日志和临时文件，保留构建缓存(重建耗时极长)
        targets.push_back({std::wstring(localAppData) + L"\\.gradle\\caches", L"Gradle缓存(临时项)", L"Gradle构建工具临时文件(保留依赖缓存)", {L"*.tmp", L"*.lock"}, false, 1});
        targets.push_back({std::wstring(localAppData) + L"\\.gradle\\daemon", L"Gradle守护进程日志", L"Gradle后台进程日志和缓存", {L"*.log", L"*.out"}, true, 1});
        // Docker Desktop
        targets.push_back({std::wstring(localAppData) + L"\\Docker\\log", L"Docker日志", L"Docker Desktop日志", {L"*.log"}, true, 1});
        targets.push_back({std::wstring(localAppData) + L"\\Docker\\profiles", L"Docker配置缓存", L"Docker Desktop配置文件(仅日志和临时)", {L"*.log", L"*.tmp", L"*.bak"}, false, 1});
        // Git
        targets.push_back({std::wstring(localAppData) + L"\\GitHub Desktop", L"GitHub Desktop缓存", L"GitHub Desktop客户端缓存", {L"*"}, true, 1});
        // WSL
        targets.push_back({std::wstring(localAppData) + L"\\wsl\\docker-desktop", L"WSL Docker数据", L"WSL Docker Desktop数据", {L"*.log", L"*.vhdx.bak"}, true, 1});
        // Flutter/Dart
        targets.push_back({std::wstring(localAppData) + L"\\.dartServer", L"Dart服务器缓存", L"Dart语言分析服务器缓存", {L"*"}, true, 2});
        targets.push_back({std::wstring(localAppData) + L"\\.pub-cache", L"Pub包缓存", L"Dart/Flutter Pub依赖包缓存(可重新下载)", {L"*"}, true, 3});
        // Unity编辑器缓存(项目导入缓存、着色器编译缓存等)
        targets.push_back({std::wstring(localAppData) + L"\\Unity", L"Unity编辑器缓存", L"Unity游戏引擎编辑器缓存(日志/临时文件)", {L"*.log", L"*.tmp", L"*.cache"}, true, 2});
        // Visual Studio组件缓存
        targets.push_back({std::wstring(localAppData) + L"\\Microsoft\\VisualStudio", L"VS组件缓存", L"Visual Studio组件和扩展缓存(可重建)", {L"*.cache", L"*.tmp", L"*.log"}, true, 2});
    }

    // ====== 更多系统路径 ======
    targets.push_back({L"C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization", L"传递优化缓存", L"Windows传递优化(P2P更新)缓存", {L"*"}, true, 5});
    targets.push_back({L"C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Windows\\INetCacheContent", L"服务IE缓存", L"系统服务账户IE缓存", {L"*"}, true, 2});
    targets.push_back({L"C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows\\INetCacheContent", L"系统IE缓存", L"SYSTEM账户IE缓存", {L"*"}, true, 2});
    targets.push_back({L"C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Temp", L"系统用户临时", L"SYSTEM账户临时文件夹", {L".tmp", L".temp", L"~$*"}, true, 3});
    targets.push_back({L"C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Temp", L"本地服务临时", L"LocalService账户临时文件夹", {L".tmp", L".temp", L"~$*"}, true, 3});
    targets.push_back({L"C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Temp", L"网络服务临时", L"NetworkService账户临时文件夹", {L".tmp", L".temp", L"~$*"}, true, 3});
    targets.push_back({L"C:\\Windows\\System32\\sru", L"SRU数据库", L"系统资源使用率数据库", {L"*.srx"}, false, 1});
    targets.push_back({L"C:\\Windows\\System32\\SleepStudy", L"睡眠研究", L"Windows电源诊断休眠报告", {L"*.xml"}, false, 1});
    targets.push_back({L"C:\\Windows\\LiveKernelReports", L"内核崩溃报告", L"Windows内核实时故障报告", {L"*.WER-internal.xml", L"*.RPT"}, true, 2});
    targets.push_back({L"C:\\Windows\\Minidump", L"小内存转储", L"Windows蓝屏小内存转储文件", {L"*.dmp"}, true, 2});
    targets.push_back({L"C:\\ProgramData\\USOShared\\Logs", L"USO日志", L"Update Session Orchestrator日志", {L"*"}, true, 1});
    targets.push_back({L"C:\\ProgramData\\Microsoft\\Diagnosis", L"诊断日志", L"Windows诊断事件跟踪日志", {L"*.etl"}, true, 2});
    targets.push_back({L"C:\\Windows\\INF", L"驱动安装缓存", L"Windows INF驱动程序安装缓存(仅.pnf)", {L"*.pnf"}, true, 1});
    targets.push_back({L"C:\\Windows\\System32\\DriverStore\\FileRepository", L"驱动存储库", L"驱动程序存储库备份(谨慎)", {L"*_del_*", L"*_bak_*"}, false, 1});
    targets.push_back({L"C:\\Windows\\System32\\FxsTmp", L"FXS临时文件", L"Windows传真服务临时文件", {L"*"}, true, 1});
    targets.push_back({L"C:\\Windows\\System32\\com\\dmp", L"COM+转储", L"COM+组件内存转储文件", {L"*.dmp"}, true, 1});
    targets.push_back({L"C:\\Windows\\rescache", L"资源缓存", L"Windows MUI多语言资源缓存", {L"*.rcdb"}, true, 1});
    targets.push_back({L"C:\\Windows\\appcompat\\Programs", L"兼容性缓存", L"应用程序兼容性缓存", {L"*.txt", L"*.xml"}, true, 1});
    targets.push_back({L"C:\\Windows\\System32\\wbem\\Logs", L"WMI日志", L"Windows管理规范(WMI)日志", {L"*.log"}, true, 1});
    targets.push_back({L"C:\\Windows\\System32\\sysprep\\Panther", L"Sysprep日志", L"系统准备工具日志", {L"*.log"}, true, 1});
    targets.push_back({L"C:\\Windows\\System32\\wdi\\LogFiles", L"WDI日志", L"Windows诊断基础设施日志", {L"*.xml"}, true, 1});
    targets.push_back({L"C:\\Windows\\CbsTemp", L"CBS临时文件", L"基于组件的服务(CBS)临时文件", {L"*"}, true, 2});
    targets.push_back({L"C:\\Windows\\Logs\\CBS", L"CBS日志", L"Windows组件安装日志(更新后可达数GB)", {L"*.log", L"*.cab", L"*.xml", L"*.persist"}, false, 1});
    targets.push_back({L"C:\\ProgramData\\Microsoft\\Search\\Data\\Applications", L"搜索索引", L"Windows搜索索引临时数据", {L"*.wid", L"*.ci"}, true, 1});
    targets.push_back({L"C:\\ProgramData\\Microsoft\\Windows Defender\\Support", L"Defender支持文件", L"Windows Defender旧版本支持文件(可自动重建)", {L"*"}, false, 1});
    targets.push_back({L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\disabled", L"禁用启动项", L"已禁用的启动项快捷方式", {L"*"}, false, 1});

    // ====== 更多软件缓存 ======
    if (localAppData[0] != L'\0') {
        // Zoom - 仅清理缓存和日志，不清理会议录制(用户重要数据)
        targets.push_back({std::wstring(localAppData) + L"\\Zoom\\data", L"Zoom缓存(仅临时)", L"Zoom视频会议临时缓存(保留录制/背景)", {L"*.cache", L"*.tmp", L"*.log"}, false, 1});
        // Telegram - 仅清理缓存，不碰用户数据
        targets.push_back({std::wstring(localAppData) + L"\\Telegram Desktop\\tdata\\user_data", L"Telegram缓存(仅临时)", L"Telegram桌面端临时缓存", {L"*.cache", L"*.tmp"}, true, 1});
        // Notion
        targets.push_back({std::wstring(localAppData) + L"\\Notion\\Cache", L"Notion缓存", L"Notion笔记应用缓存", {L"*"}, true, 2});
        // OBS Studio
        targets.push_back({std::wstring(localAppData) + L"\\obs-studio\\crashes", L"OBS崩溃报告", L"OBS Studio崩溃转储", {L"*.dmp"}, false, 1});
        // Blender - 渲染缓存可能包含重要中间结果，仅清理临时文件
        targets.push_back({std::wstring(localAppData) + L"\\Blender Foundation\\Blender\\cache", L"Blender缓存(临时项)", L"Blender 3D渲染临时文件", {L"*.tmp", L".blend*~"}, false, 1});
        // Figma - 仅清理缓存文件，保留离线项目数据
        targets.push_back({std::wstring(localAppData) + L"\\Figma", L"Figma缓存(仅临时)", L"Figma设计工具临时缓存(保留离线项目)", {L"*.cache", L"*.tmp", L"*.log"}, false, 1});
        // MATLAB
        targets.push_back({std::wstring(localAppData) + L"\\MathWorks", L"MATLAB缓存(临时项)", L"MATLAB数学工具临时文件", {L"*.log", L"*.tmp"}, false, 1});
        // JetBrains IDEs - 仅清理日志和崩溃报告，保留索引和构建缓存
        targets.push_back({std::wstring(localAppData) + L"\\JetBrains", L"JetBrains缓存(日志/崩溃)", L"JetBrains全家桶IDE日志和崩溃报告", {L"*.log", L"*.dmp", L"*.hprof"}, false, 1});
        // VLC
        targets.push_back({std::wstring(localAppData) + L"\\vlc\\cache", L"VLC缓存", L"VLC播放器缓存", {L"*"}, true, 2});
        // Thunderbird - 仅清理缓存，不碰邮件数据
        targets.push_back({std::wstring(localAppData) + L"\\Thunderbird\\Profiles", L"Thunderbird缓存(仅临时)", L"Mozilla Thunderbird邮件客户端缓存", {L"*.cache", L"*.cache2", L"*.tmp"}, true, 1});
        // Foxmail
        targets.push_back({std::wstring(localAppData) + L"\\Foxmail\\Temp", L"Foxmail临时文件", L"Foxmail邮件客户端临时文件", {L"*"}, true, 2});
        // 360安全卫士
        targets.push_back({std::wstring(localAppData) + L"\\360safe", L"360缓存", L"360安全卫士缓存", {L"*"}, true, 2});
        // 金山毒霸/WPS - 不清理！WPS自动保存草稿(autosave)在此目录下
        // 误删将导致用户无法恢复未保存文档，属于关键用户数据
        // targets.push_back({std::wstring(localAppData) + L"\\Kingsoft", ...}); // 已禁用:含WPS自动保存
        // 迅雷 - 仅清理临时文件和未完成下载的碎片，保留已下载文件
        targets.push_back({std::wstring(localAppData) + L"\\ThunderDownload", L"迅雷缓存(临时项)", L"迅雷下载工具临时文件(保留已下载)", {L"*.tmp", L".part*", L".td"}, false, 1});
        // IDA Pro - 仅清理临时文件，绝对不能删.id0/.id1/.nam/.til数据库文件
        targets.push_back({std::wstring(localAppData) + L"\\IDA", L"IDA缓存(仅临时)", L"IDA Pro逆向工程工具临时文件(保留分析数据库)", {L"*.tmp", L"*.log"}, false, 1});
        // Wireshark
        targets.push_back({std::wstring(localAppData) + L"\\Wireshark", L"Wireshark缓存", L"Wireshark抓包工具缓存", {L"*"}, true, 1});
        // WinRAR
        targets.push_back({std::wstring(localAppData) + L"\\WinRAR", L"WinRAR临时文件", L"WinRAR解压临时文件", {L"*"}, true, 1});
        // 7-Zip
        targets.push_back({std::wstring(localAppData) + L"\\7-Zip", L"7-Zip临时文件", L"7-Zip解压临时文件", {L"*"}, true, 1});
        // Bandizip
        targets.push_back({std::wstring(localAppData) + L"\\Bandizip", L"Bandizip临时文件", L"Bandizip压缩工具临时文件", {L"*"}, true, 1});
        // Snipaste
        targets.push_back({std::wstring(localAppData) + L"\\Snipaste", L"Snipaste缓存", L"Snipaste截图工具缓存", {L"*"}, true, 1});
        // Everything搜索
        targets.push_back({std::wstring(localAppData) + L"\\Everything", L"Everything缓存", L"Everything文件搜索工具缓存", {L"*"}, true, 1});
        // Listary
        targets.push_back({std::wstring(localAppData) + L"\\Listary", L"Listary缓存", L"Listary文件搜索增强工具缓存", {L"*"}, true, 1});
        // PotPlayer
        targets.push_back({std::wstring(localAppData) + L"\\Daum\\PotPlayerMini\\Capture", L"PotPlayer截图", L"PotPlayer播放器自动截图缓存", {L"*"}, true, 2});
        // QQ音乐 - 仅清理临时缓存，保留离线下载的音乐
        targets.push_back({std::wstring(localAppData) + L"Tencent\\QQMusic\\Cache", L"QQ音乐缓存(临时项)", L"QQ音乐音频临时缓存", {L"*.tmp", L"*.qmc2~"}, false, 1});
        // 网易云音乐
        targets.push_back({std::wstring(localAppData) + L"NetEase\\CloudMusic\\Cache", L"网易云缓存(临时项)", L"网易云音乐临时缓存", {L"*.tmp"}, false, 1});
        // 酷狗音乐
        targets.push_back({std::wstring(localAppData) + L"KuGou\\Cache", L"酷狗缓存(临时项)", L"酷狗音乐临时缓存", {L"*.tmp", L"*.kgm~"}, false, 1});
        // NVIDIA 非着色器驱动缓存(安装临时、崩溃报告、Display容器日志)
        // 注意: 不清理D3DSCache/NVIDIA DXCache等着色器缓存(重建会导致游戏卡顿)
        targets.push_back({std::wstring(localAppData) + L"NVIDIA", L"NVIDIA日志(非着色器)", L"NVIDIA显卡驱动日志/崩溃报告/临时文件(保留着色器缓存)", {L"*.log", L"*.dmp", L"*.tmp"}, true, 2});
    }

    return targets;
}

void GarbageCleaner::ScanDirectory(const ScanTarget& target, std::vector<GarbageFileInfo>& localFiles, int currentDepth) {
    if (g_stopRequested.load() || (target.maxDepth >= 0 && currentDepth > target.maxDepth)) {
        return;
    }

    std::wstring basePath = target.path;
    if (basePath.empty()) {
        return;
    }

    static const wchar_t* systemPathPrefixes[] = {
        L"\\windows\\system32\\",
        L"\\windows\\syswow64\\",
        L"\\program files\\",
        L"\\program files (x86)\\",
        L"\\windows\\winsxs\\",
        L"\\programdata\\microsoft\\",
        L"\\$recycle.bin\\",
        L"\\system volume information\\",
        L"\\perflogs\\",
        // ====== Visual Studio 关键目录 (绝对不可删除) ======
        L"\\microsoft visual studio\\",            // VS 主程序 (2022/2019/2017 等)
        L"\\msbuild\\",                            // MSBuild 工具链
        L"\\windows kits\\",                       // Windows SDK
        L"\\dotnet\\",                             // .NET SDK/Runtime
        L"\\dotnetfx\\",                           // .NET Framework
        L"\\microsoft sdk\\",                      // 旧版 Microsoft SDK
        L"\\windows performance toolkit\\",        // Windows Performance Toolkit
        L"\\microsoft sql server\\",               // SQL Server
        L"\\microsoft office\\",                   // Office (在 Program Files 下)
        L"\\microsoft visualstudio\\",            // VS 共享组件/扩展
        L"\\vs_enterprise\\",                      // VS Enterprise 版
        L"\\vs_professional\\",                    // VS Professional 版
        L"\\vs_community\\",                       // VS Community 版
        // ====== 编译器/工具链 ======
        L"\\mingw\\",
        L"\\cygwin\\",
        L"\\msys2\\",
        L"\\llvm\\",
        L"\\clion\\",
        L"\\rider\\",
        L"\\android studio\\",
        L"\\intellij idea\\",
        L"\\pycharm\\",
        L"\\webstorm\\",
        L"\\phpstorm\\",
        L"\\goland\\",
        L"\\datagrip\\",
        // ====== 游戏平台安装目录 ======
        L"\\steam\\",
        L"\\steamlibrary\\",
        L"\\epic games\\",
        L"\\riot games\\",
        L"\\battlenet\\",
        L"\\origin\\",
        L"\\ubisoft game launcher\\",
        // ====== 关键系统服务 ======
        L"\\appdata\\local\\microsoft\\onedrive\\", // OneDrive 主目录(非缓存)
        L"\\appdata\\local\\google\\chrome\\user data\\", // Chrome 用户数据(非缓存)
        L"\\appdata\\local\\microsoft\\edge\\user data\\", // Edge 用户数据
        L"\\appdata\\roaming\\microsoft\\",        // 用户漫游配置
        L"\\appdata\\local\\packages\\",            // UWP 应用
    };

    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW((basePath + L"\\*").c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if (g_stopRequested.load()) break;

        std::wstring filename = findData.cFileName;

        if (filename == L"." || filename == L"..") {
            continue;
        }

        std::wstring fullPath = basePath + L"\\" + filename;
        g_progress.scannedFiles.fetch_add(1, std::memory_order_relaxed);

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (target.scanSubdirs && currentDepth < target.maxDepth) {
                ScanDirectory({fullPath, target.category, target.description, target.extensions, target.scanSubdirs, target.maxDepth}, localFiles, currentDepth + 1);
            }
        }
        else {
            if (MatchExtension(filename, target.extensions)) {
                std::wstring lowerPath = fullPath;
                for (auto& c : lowerPath) c = towlower(c);

                bool isProtected = false;
                for (const auto& prefix : systemPathPrefixes) {
                    if (lowerPath.find(prefix) != std::wstring::npos) {
                        isProtected = true;
                        break;
                    }
                }

                if (isProtected) {
                    FindNextFileW(hFind, &findData);
                    continue;
                }

                ULARGE_INTEGER fileSize;
                fileSize.LowPart = findData.nFileSizeLow;
                fileSize.HighPart = findData.nFileSizeHigh;

                localFiles.push_back({fullPath, fileSize.QuadPart, target.category, target.description});
                g_progress.foundFiles.fetch_add(1, std::memory_order_relaxed);
                g_progress.totalSize.fetch_add(fileSize.QuadPart, std::memory_order_relaxed);
            }
        }
    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
}

DWORD WINAPI GarbageCleaner::ScanThreadProc(LPVOID lpParam) {
    ScanTarget* target = static_cast<ScanTarget*>(lpParam);
    std::vector<GarbageFileInfo> localFiles;

    try {
        ScanDirectory(*target, localFiles);
    }
    catch (...) {
    }

    if (!localFiles.empty()) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_garbageFiles.insert(g_garbageFiles.end(), localFiles.begin(), localFiles.end());
    }

    g_progress.runningThreads.fetch_sub(1, std::memory_order_relaxed);
    delete target;
    return 0;
}

void CALLBACK GarbageCleaner::DeleteFileCallback(PTP_CALLBACK_INSTANCE instance, PVOID context) {
    DeleteTaskContext* task = static_cast<DeleteTaskContext*>(context);
    if (!task) return;

    // 快速检查停止信号
    if (task->stopFlag->load(std::memory_order_relaxed)) {
        task->failedCount->fetch_add(1, std::memory_order_relaxed);
        task->processedCount->fetch_add(1, std::memory_order_relaxed);
        return;
    }

    // 直接调用 DeleteFileW (路径已经在主线程中验证过)
    BOOL result = DeleteFileW(task->path.c_str());
    if (result) {
        task->deletedCount->fetch_add(1, std::memory_order_relaxed);
        task->deletedSize->fetch_add(task->size, std::memory_order_relaxed);
    } else {
        // 快速错误处理
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
            task->deletedCount->fetch_add(1, std::memory_order_relaxed);
        } else if (err == ERROR_ACCESS_DENIED) {
            // 尝试移除只读属性
            DWORD attr = GetFileAttributesW(task->path.c_str());
            if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_READONLY)) {
                SetFileAttributesW(task->path.c_str(), attr & ~FILE_ATTRIBUTE_READONLY);
                if (DeleteFileW(task->path.c_str())) {
                    task->deletedCount->fetch_add(1, std::memory_order_relaxed);
                    task->deletedSize->fetch_add(task->size, std::memory_order_relaxed);
                } else {
                    task->failedCount->fetch_add(1, std::memory_order_relaxed);
                }
            } else {
                task->failedCount->fetch_add(1, std::memory_order_relaxed);
            }
        } else {
            task->failedCount->fetch_add(1, std::memory_order_relaxed);
        }
    }
    task->processedCount->fetch_add(1, std::memory_order_relaxed);
}

void GarbageCleaner::BatchDeleteByDirectory(const std::vector<GarbageFileInfo>& files, int& deletedCount, int& failedCount, uint64_t& deletedSize, int maxCmdLength) {
    // [高性能优化策略]
    // 1. 预过滤: 主线程先批量检查受保护路径,只提交安全任务
    // 2. 任务对象池: 预分配任务对象,避免每文件 new/delete
    // 3. 快速路径: critical 检查仅 1 次,任务中直接删除
    // 4. 内存序优化: relaxed 内存序减少 CPU 内存屏障
    if (files.empty()) {
        deletedCount = 0;
        failedCount = 0;
        deletedSize = 0;
        return;
    }

    // [优化1] 主线程预过滤 - 检查所有文件路径
    std::vector<DeleteTaskContext> taskPool;
    taskPool.reserve(files.size());
    int preFilteredCount = 0;
    std::atomic<int> preFilteredAtomic(0);

    for (const auto& f : files) {
        DeleteTaskContext task;
        task.path = f.path;
        task.size = f.size;
        // 这些指针稍后赋值
        task.deletedCount = nullptr;
        task.failedCount = nullptr;
        task.deletedSize = nullptr;
        task.processedCount = nullptr;
        task.stopFlag = nullptr;
        task.totalCount = 0;

        // 快速安全检查 (主线程执行,无需重复)
        // 使用简单快速算法: 只检查是否包含关键子串
        static const wchar_t* criticalPaths[] = {
            L"\\microsoft visual studio\\",
            L"\\windows kits\\",
            L"\\msbuild\\",
            L"\\dotnet\\packs\\",
            L"\\dotnet\\sdk\\",
            L"\\dotnet\\shared\\",
            L"\\vc\\tools\\",
            L"\\vc\\include\\",
            L"\\vc\\lib\\",
            L"\\vc\\atlmfc\\",
        };
        bool isCritical = false;
        // 单次扫描,使用 towlower 优化的内联函数
        for (auto& c : task.path) {
            if (c >= L'A' && c <= L'Z') c = c - L'A' + L'a';
        }
        for (auto prefix : criticalPaths) {
            if (wcsstr(task.path.c_str(), prefix) != nullptr) {
                isCritical = true;
                break;
            }
        }

        if (isCritical) {
            preFilteredCount++;
        } else {
            taskPool.push_back(std::move(task));
        }
    }

    if (preFilteredCount > 0) {
        std::wcout << L"[安全] 预过滤跳过 " << preFilteredCount << L" 个受保护文件" << std::endl;
    }

    int actualTaskCount = (int)taskPool.size();
    if (actualTaskCount == 0) {
        deletedCount = 0;
        failedCount = preFilteredCount;
        deletedSize = 0;
        return;
    }

    // [优化2] 共享原子计数器
    std::atomic<int> deletedCountAtomic(0);
    std::atomic<int> failedCountAtomic(preFilteredCount);  // 计入预过滤数
    std::atomic<uint64_t> deletedSizeAtomic(0);
    std::atomic<int> processedCount(0);
    std::atomic<bool> stopFlag(false);

    // 填充共享指针
    for (auto& task : taskPool) {
        task.deletedCount = &deletedCountAtomic;
        task.failedCount = &failedCountAtomic;
        task.deletedSize = &deletedSizeAtomic;
        task.processedCount = &processedCount;
        task.stopFlag = &stopFlag;
        task.totalCount = actualTaskCount;
    }

    // [优化3] 线程池环境
    TP_CALLBACK_ENVIRON pcbe;
    InitializeThreadpoolEnvironment(&pcbe);

    PTP_CLEANUP_GROUP cleanupGroup = CreateThreadpoolCleanupGroup();
    SetThreadpoolCallbackCleanupGroup(&pcbe, cleanupGroup, nullptr);

    PTP_POOL pool = CreateThreadpool(nullptr);
    if (!pool) {
        // 回退到串行删除
        for (auto& task : taskPool) {
            if (DeleteFileW(task.path.c_str())) {
                deletedCountAtomic.fetch_add(1);
                deletedSizeAtomic.fetch_add(task.size);
            } else {
                failedCountAtomic.fetch_add(1);
            }
        }
        deletedCount = deletedCountAtomic.load();
        failedCount = failedCountAtomic.load();
        deletedSize = deletedSizeAtomic.load();
        return;
    }

    // [优化4] 智能线程数: 不再硬编码 4096
    // Windows 默认线程池 500 个并发足够,设置过高反而降低性能
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    DWORD numCores = si.dwNumberOfProcessors;
    // 物理核心 * 4 已经是极限(IO 密集型操作)
    DWORD maxThreads = (std::min)((DWORD)4096, numCores * 8);
    DWORD minThreads = (std::min)((DWORD)16, numCores * 2);
    SetThreadpoolThreadMaximum(pool, maxThreads);
    SetThreadpoolThreadMinimum(pool, minThreads);
    SetThreadpoolCallbackPool(&pcbe, pool);

    // 进度显示线程
    std::thread progressThread([&]() {
        int lastDisplayed = 0;
        while (processedCount.load(std::memory_order_relaxed) < actualTaskCount &&
               !stopFlag.load(std::memory_order_relaxed)) {
            int cur = processedCount.load(std::memory_order_relaxed);
            if (cur - lastDisplayed >= 5000 || cur == actualTaskCount) {
                lastDisplayed = cur;
                std::wcout << L"\r[删除中] " << cur << L"/" << actualTaskCount
                           << L" | 成功 " << deletedCountAtomic.load(std::memory_order_relaxed)
                           << L" | 失败 " << failedCountAtomic.load(std::memory_order_relaxed)
                           << L" | " << FormatSize(deletedSizeAtomic.load(std::memory_order_relaxed))
                           << L"      " << std::flush;
            }
            Sleep(100);
        }
        std::wcout << L"\r[删除中] " << actualTaskCount << L"/" << actualTaskCount
                   << L" | 成功 " << deletedCountAtomic.load()
                   << L" | 失败 " << failedCountAtomic.load()
                   << L" | " << FormatSize(deletedSizeAtomic.load())
                   << L"      " << std::endl;
    });

    // 批量提交任务
    for (auto& task : taskPool) {
        // 关键: 传 &task (栈/vector 中对象地址),而非 new
        TrySubmitThreadpoolCallback(DeleteFileCallback, &task, &pcbe);
    }

    // 等待所有任务完成
    CloseThreadpoolCleanupGroupMembers(cleanupGroup, FALSE, nullptr);

    stopFlag.store(true);
    if (progressThread.joinable()) {
        progressThread.join();
    }

    CloseThreadpoolCleanupGroup(cleanupGroup);
    CloseThreadpool(pool);

    deletedCount = deletedCountAtomic.load();
    failedCount = failedCountAtomic.load();
    deletedSize = deletedSizeAtomic.load();
}

void GarbageCleaner::StartCleanup() {
    DMSP_VERIFY(0x2005);  // 垃圾清理子函数 - 二级验证
    g_garbageFiles.clear();
    g_progress.scannedFiles.store(0);
    g_progress.foundFiles.store(0);
    g_progress.totalSize.store(0);
    g_progress.runningThreads.store(0);
    g_progress.startTime = std::chrono::steady_clock::now();
    g_stopRequested.store(false);

    std::wcout << L"\n========================================" << std::endl;
    std::wcout << L"           C盘垃圾清理" << std::endl;
    std::wcout << L"========================================" << std::endl;

    std::vector<ScanTarget> targets = GetScanTargets();

    std::wcout << L"\n[扫描] 正在启动多线程扫描..." << std::endl;
    std::wcout << L"[信息] 共 " << targets.size() << L" 个扫描目标" << std::endl;

    std::vector<HANDLE> threads;

    for (const auto& target : targets) {
        ScanTarget* pTarget = new ScanTarget(target);
        g_progress.runningThreads.fetch_add(1, std::memory_order_relaxed);
        HANDLE hThread = CreateThread(nullptr, 0, ScanThreadProc, pTarget, 0, nullptr);
        if (hThread) {
            threads.push_back(hThread);
        }
    }

    std::wcout << L"[扫描] 已启动 " << threads.size() << L" 个扫描线程" << std::endl;

    while (g_progress.runningThreads.load() > 0) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - g_progress.startTime).count();

        std::wcout << L"\r[扫描中] 已扫描 " << g_progress.scannedFiles.load()
                   << L" 个文件 | 发现 " << g_progress.foundFiles.load()
                   << L" 个垃圾 | 大小 " << FormatSize(g_progress.totalSize.load())
                   << L" | 耗时 " << elapsed << L"s      " << std::flush;

        Sleep(500);
    }

    std::cout << std::endl;

    for (HANDLE hThread : threads) {
        CloseHandle(hThread);
    }

    if (g_garbageFiles.empty()) {
        std::wcout << L"\n[完成] 未发现可清理的垃圾文件" << std::endl;
        return;
    }

    std::map<std::wstring, std::pair<uint64_t, int>> categoryStats;
    for (const auto& file : g_garbageFiles) {
        categoryStats[file.category].first += file.size;
        categoryStats[file.category].second++;
    }

    std::wcout << L"\n[结果] 垃圾文件统计:" << std::endl;
    std::wcout << L"----------------------------------------" << std::endl;
    uint64_t totalSize = 0;
    int totalCount = 0;
    for (const auto& cat : categoryStats) {
        std::wcout << L"  " << std::left << std::setw(20) << cat.first
                   << L": " << std::right << std::setw(5) << cat.second.second << L" 个"
                   << L" | " << FormatSize(cat.second.first) << std::endl;
        totalSize += cat.second.first;
        totalCount += cat.second.second;
    }
    std::wcout << L"----------------------------------------" << std::endl;
    std::wcout << L"  " << std::left << std::setw(20) << L"总计"
               << L": " << std::right << std::setw(5) << totalCount << L" 个"
               << L" | " << FormatSize(totalSize) << std::endl;

    std::wcout << L"\n是否清理这些文件? (Y: 清理, N: 取消): ";
    wchar_t choice;
    std::wcin >> choice;
    std::wcin.ignore();

    if (choice != L'y' && choice != L'Y') {
        std::wcout << L"[取消] 操作已取消" << std::endl;
        return;
    }

    std::wcout << L"\n[删除] 正在清理垃圾文件..." << std::endl;

    int deletedCount = 0;
    int failedCount = 0;
    uint64_t deletedSize = 0;

    BatchDeleteByDirectory(g_garbageFiles, deletedCount, failedCount, deletedSize);

    std::cout << std::endl;

    std::wcout << L"\n[完成] 清理完成!" << std::endl;
    std::wcout << L"  删除成功: " << deletedCount << L" 个 | " << FormatSize(deletedSize) << std::endl;
    std::wcout << L"  删除失败: " << failedCount << L" 个 (可能被其他程序占用)" << std::endl;

    g_garbageFiles.clear();
}

// ============================================================================
// 静态成员定义
// ============================================================================

GarbageCleaner::ScanProgress GarbageCleaner::g_progress;
std::vector<GarbageCleaner::GarbageFileInfo> GarbageCleaner::g_garbageFiles;
std::mutex GarbageCleaner::g_mutex;
std::atomic<bool> GarbageCleaner::g_stopRequested{false};
