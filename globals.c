#include "common.h"

// --- 全局变量定义 (Definitions) ---
// 注意：这里没有 extern 关键字

ProxyConfig g_proxyConfig;
volatile BOOL g_proxyRunning = FALSE;
SOCKET g_listen_sock = INVALID_SOCKET;
SSL_CTX *g_ssl_ctx = NULL;
HANDLE hProxyThread = NULL;
NOTIFYICONDATAW nid;
HWND hwnd;
HMENU hMenu = NULL, hNodeSubMenu = NULL;
HWND hLogViewerWnd = NULL;
HFONT hLogFont = NULL;
HFONT hAppFont = NULL;
wchar_t** nodeTags = NULL;
int nodeCount = 0;
wchar_t currentNode[64] = L"";
wchar_t g_editingTag[256] = {0};
BOOL g_isIconVisible = TRUE;
wchar_t g_iniFilePath[MAX_PATH] = {0};
UINT g_hotkeyModifiers = MOD_CONTROL | MOD_ALT; 
UINT g_hotkeyVk = 'H';                          
int g_localPort = 10809;
int g_hideTrayStart = 0; 
int g_nEditScrollPos = 0;
int g_nEditContentHeight = 0;

// 抗封锁配置
BOOL g_enableChromeCiphers = TRUE;
BOOL g_enableALPN = TRUE;
// 默认启用分片
BOOL g_enableFragment = TRUE; 
// 最佳分片默认值：5 - 20 字节
int g_fragSizeMin = 5;
int g_fragSizeMax = 20;
int g_fragDelayMs = 2;

// 默认启用 Padding
BOOL g_enablePadding = TRUE;
// 最佳 Padding 默认值：100 - 500 字节
// 确保足够大以掩盖 HTTP 请求头特征，且区间足够大以提供随机性
int g_padSizeMin = 100;
int g_padSizeMax = 500;

int g_uaPlatformIndex = 0; 
char g_userAgentStr[512] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

const wchar_t* UA_PLATFORMS[] = { L"Windows", L"iOS", L"Android", L"macOS", L"Linux" };
const char* UA_TEMPLATES[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
};
