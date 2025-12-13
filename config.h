#ifndef CONFIG_H
#define CONFIG_H

#include "common.h"
#include "cJSON.h"

// 全局配置变量
extern int g_localPort;
extern int g_hotkeyModifiers;
extern int g_hotkeyVk;
extern int g_hideTrayStart;

// 抗封锁策略配置
extern int g_enableChromeCiphers;
extern int g_enableALPN;
extern int g_enableFragment;
extern int g_fragSizeMin;
extern int g_fragSizeMax;
extern int g_fragDelayMs;
extern int g_enablePadding;
extern int g_padSizeMin;
extern int g_padSizeMax;
extern int g_uaPlatformIndex;
extern char g_userAgentStr[512];

// 节点管理相关
extern wchar_t g_iniFilePath[MAX_PATH];
extern struct ProxyConfig g_proxyConfig;
extern wchar_t** nodeTags;
extern int nodeCount;
extern wchar_t currentNode[64];

// --- 新增：订阅管理系统 ---
#define MAX_SUBS 20

typedef struct {
    BOOL enabled;   // 是否启用
    char url[512];  // 订阅地址
} Subscription;

extern Subscription g_subs[MAX_SUBS];
extern int g_subCount;

// 函数声明
void LoadSettings();
void SaveSettings();
void SetAutorun(BOOL enable);
BOOL IsAutorun();
void ParseTags();
void SwitchNode(const wchar_t* tag);
void ParseNodeConfigToGlobal(cJSON *node);
void DeleteNode(const wchar_t* tag);
BOOL AddNodeToConfig(cJSON* newNode);

// 协议解析辅助函数
cJSON* ParseVmess(const char* link);
cJSON* ParseShadowsocks(const char* link);
cJSON* ParseVlessOrTrojan(const char* link);
cJSON* ParseSocks(const char* link);

int ImportFromClipboard();
void ToggleTrayIcon();

// --- 新增：更新所有订阅 ---
// forceMsg: 是否强制弹窗/记录日志（自动更新时设为FALSE以避免打扰）
int UpdateAllSubscriptions(BOOL forceMsg);

#endif // CONFIG_H
