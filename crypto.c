#include "crypto.h"
#include "utils.h"
#include <stdlib.h>

// ---------------------- BIO Fragmentation Implementation ----------------------

// 定义 BIO 控制命令
#define BIO_C_SET_FRAG_CONFIG 101

// 分片配置结构体
typedef struct {
    int max_splits;    // 最大分片次数
    int min_size;      // 最小包大小
    int max_size;      // 最大包大小
    int delay_ms;      // 延时
    int first_packet_sent; // 状态标记
} FragCtx;

static int frag_write(BIO *b, const char *in, int inl);
static int frag_read(BIO *b, char *out, int outl);
static long frag_ctrl(BIO *b, int cmd, long num, void *ptr);
static int frag_new(BIO *b);
static int frag_free(BIO *b);

static BIO_METHOD *method_frag = NULL;

BIO_METHOD *BIO_f_fragment(void) {
    if (method_frag == NULL) {
        method_frag = BIO_meth_new(BIO_TYPE_FILTER, "Fragmentation Filter");
        BIO_meth_set_write(method_frag, frag_write);
        BIO_meth_set_read(method_frag, frag_read);
        BIO_meth_set_ctrl(method_frag, frag_ctrl);
        BIO_meth_set_create(method_frag, frag_new);
        BIO_meth_set_destroy(method_frag, frag_free);
    }
    return method_frag;
}

static int frag_new(BIO *b) {
    FragCtx *ctx = (FragCtx *)malloc(sizeof(FragCtx));
    if(!ctx) return 0;
    // 默认初始化 (防止未配置时崩溃)
    ctx->first_packet_sent = 0;
    ctx->max_splits = 7;
    ctx->min_size = 1;
    ctx->max_size = 20;
    ctx->delay_ms = 1;
    BIO_set_data(b, ctx);
    BIO_set_init(b, 1);
    return 1;
}

static int frag_free(BIO *b) {
    if (b == NULL) return 0;
    FragCtx *ctx = (FragCtx *)BIO_get_data(b);
    if (ctx) { free(ctx); BIO_set_data(b, NULL); }
    return 1;
}

// [核心逻辑] 根据 Context 中的配置进行分片
static int frag_write(BIO *b, const char *in, int inl) {
    FragCtx *ctx = (FragCtx *)BIO_get_data(b);
    BIO *next = BIO_next(b);
    if (!ctx || !next) return 0;

    // 仅针对握手阶段 (TLS ClientHello)
    if (inl > 0 && ctx->first_packet_sent == 0) {
        ctx->first_packet_sent = 1; 

        int bytes_sent = 0;
        int remaining = inl;
        int split_count = 0;

        while (remaining > 0) {
            // 达到最大切分次数后，剩余数据一次性发送
            if (split_count >= ctx->max_splits) {
                int ret = BIO_write(next, in + bytes_sent, remaining);
                if (ret <= 0) return (bytes_sent > 0 ? bytes_sent : ret);
                bytes_sent += ret;
                break; // 完成
            }

            // 动态计算包大小
            int chunk_size;
            int range = ctx->max_size - ctx->min_size;
            if (range < 0) range = 0;
            
            chunk_size = ctx->min_size + (range > 0 ? (rand() % (range + 1)) : 0);
            if (chunk_size < 1) chunk_size = 1;
            if (chunk_size > remaining) chunk_size = remaining;

            int ret = BIO_write(next, in + bytes_sent, chunk_size);
            if (ret <= 0) return (bytes_sent > 0 ? bytes_sent : ret);

            bytes_sent += ret;
            remaining -= ret;
            split_count++;

            // 延时策略：仅在前几次且有剩余数据时延时
            // 对于强力模式，我们允许更多次的延时
            if (remaining > 0 && ctx->delay_ms > 0) {
                 Sleep(rand() % (ctx->delay_ms + 1));
            }
        }
        return bytes_sent;
    }
    
    return BIO_write(next, in, inl);
}

static int frag_read(BIO *b, char *out, int outl) {
    BIO *next = BIO_next(b);
    if (!next) return 0;
    return BIO_read(next, out, outl);
}

static long frag_ctrl(BIO *b, int cmd, long num, void *ptr) {
    BIO *next = BIO_next(b);
    if (!next) return 0;
    
    // 处理自定义配置命令
    if (cmd == BIO_C_SET_FRAG_CONFIG) {
        FragCtx *ctx = (FragCtx *)BIO_get_data(b);
        FragCtx *new_cfg = (FragCtx *)ptr;
        if (ctx && new_cfg) {
            ctx->max_splits = new_cfg->max_splits;
            ctx->min_size = new_cfg->min_size;
            ctx->max_size = new_cfg->max_size;
            ctx->delay_ms = new_cfg->delay_ms;
        }
        return 1;
    }
    
    return BIO_ctrl(next, cmd, num, ptr);
}

// ---------------------- End BIO Implementation ----------------------

void FreeGlobalSSLContext() {
    if (g_ssl_ctx) { SSL_CTX_free(g_ssl_ctx); g_ssl_ctx = NULL; }
}

void init_openssl_global() {
    if (g_ssl_ctx) return;
    SSL_library_init(); OpenSSL_add_all_algorithms(); SSL_load_error_strings();
    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_ssl_ctx) return;
    SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(g_ssl_ctx, TLS1_3_VERSION);

    if (g_enableChromeCiphers) {
        const char *chrome_ciphers = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA";
        SSL_CTX_set_cipher_list(g_ssl_ctx, chrome_ciphers);
        SSL_CTX_set_options(g_ssl_ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
        SSL_CTX_set_session_cache_mode(g_ssl_ctx, SSL_SESS_CACHE_CLIENT);
        log_msg("[Security] Chrome Cipher Suites Enabled");
    } else {
        log_msg("[Security] Standard OpenSSL Cipher Suites");
    }
    // (省略 CA 加载代码，保持原样即可)
    SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL); 
}

// [修改] 支持 mode 参数
// mode 0: 使用 set.ini 中的配置 (温和)
// mode 1: 强制使用强力配置 (智能重试)
int tls_init_connect(TLSContext *ctx, int mode) {
    ctx->ssl = SSL_new(g_ssl_ctx);
    
    if (g_enablePadding) {
        int range = g_padSizeMax - g_padSizeMin;
        if (range < 0) range = 0;
        int blockSize = g_padSizeMin + (range > 0 ? (rand() % (range + 1)) : 0);
        if (blockSize > 200) blockSize = 200; 
        if (blockSize > 0) SSL_set_block_padding(ctx->ssl, blockSize);
    }

    BIO *bio = BIO_new_socket(ctx->sock, BIO_NOCLOSE);
    
    if (g_enableFragment) {
        BIO *frag = BIO_new(BIO_f_fragment());
        
        // 配置分片参数
        FragCtx cfg;
        if (mode == 0) {
            // Mode 0: 温和策略 (日常使用，稳定)
            cfg.max_splits = 7;           // 切 7 刀
            cfg.min_size = g_fragSizeMin; // 读取配置
            cfg.max_size = g_fragSizeMax;
            cfg.delay_ms = g_fragDelayMs; // 读取配置 (通常 1-2ms)
        } else {
            // Mode 1: 强力策略 (突破封锁，仅在重试时使用)
            cfg.max_splits = 40;          // 切 40 刀，足够碎
            cfg.min_size = 1;             // 极小包
            cfg.max_size = 3;             // 1-3 字节
            cfg.delay_ms = 3;             // 稍微增加延时确保乱序效果
            log_msg("[Smart-Frag] Applying Aggressive Strategy!");
        }
        
        // 发送配置给 BIO
        BIO_ctrl(frag, BIO_C_SET_FRAG_CONFIG, 0, &cfg);
        
        bio = BIO_push(frag, bio);
    }
    
    SSL_set_bio(ctx->ssl, bio, bio);
    
    const char *sni_name = (strlen(g_proxyConfig.sni) ? g_proxyConfig.sni : g_proxyConfig.host);
    SSL_set_tlsext_host_name(ctx->ssl, sni_name);
    
    if (g_enableALPN) {
        unsigned char alpn_protos[] = { 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
        SSL_set_alpn_protos(ctx->ssl, alpn_protos, sizeof(alpn_protos));
    }

    return (SSL_connect(ctx->ssl) == 1) ? 0 : -1;
}

// (其余 tls_write, tls_read 等函数保持原样)
int tls_write(TLSContext *ctx, const char *data, int len) {
    if (!ctx->ssl) return -1;
    int written = 0;
    while (written < len) {
        int ret = SSL_write(ctx->ssl, data + written, len - written);
        if (ret > 0) { written += ret; } 
        else {
            int err = SSL_get_error(ctx->ssl, ret);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) { Sleep(1); continue; }
            return -1; 
        }
    }
    return written;
}

int tls_read(TLSContext *ctx, char *out, int max) {
    if (!ctx->ssl) return -1;
    int ret = SSL_read(ctx->ssl, out, max);
    if (ret <= 0) {
        int err = SSL_get_error(ctx->ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return 0;
        if (err == SSL_ERROR_ZERO_RETURN) return -1;
        return -1;
    }
    return ret;
}

int tls_read_exact(TLSContext *ctx, char *buf, int len) {
    int total = 0;
    while (total < len) {
        int ret = tls_read(ctx, buf + total, len - total);
        if (ret < 0) return 0; 
        if (ret == 0) { Sleep(1); continue; } 
        total += ret;
    }
    return 1;
}

void tls_close(TLSContext *ctx) {
    if (ctx->ssl) { SSL_shutdown(ctx->ssl); SSL_free(ctx->ssl); ctx->ssl = NULL; }
}

int build_ws_frame(const char *in, int len, char *out) {
    out[0] = 0x82; uint8_t mask[4]; *(uint32_t*)mask = GetTickCount(); 
    if (len < 126) { out[1] = 0x80 | len; memcpy(out+2, mask, 4); for(int i=0;i<len;i++) out[6+i] = in[i]^mask[i%4]; return 6+len; } 
    else if (len <= 65535) { out[1] = 0x80 | 126; out[2] = (len>>8)&0xFF; out[3] = len&0xFF; memcpy(out+4, mask, 4); for(int i=0;i<len;i++) out[8+i] = in[i]^mask[i%4]; return 8+len; }
    return -1; 
}

int check_ws_frame(unsigned char *in, int len, int *head_len, int *payload_len) {
    if(len < 2) return 0;
    int hl = 2; int pl = in[1] & 0x7F;
    if (pl == 126) { if (len < 4) return 0; hl = 4; pl = (in[2] << 8) | in[3]; } 
    else if (pl == 127) { if (len < 10) return 0; hl = 10; pl = 65536; }
    if (len < hl + pl) return 0;
    *head_len = hl; *payload_len = pl;
    return hl + pl; 
}

int ws_read_payload_exact(TLSContext *tls, char *out_buf, int expected_len) {
    char raw_head[16];
    if (!tls_read_exact(tls, raw_head, 2)) return 0;
    int payload_len = raw_head[1] & 0x7F;
    if (payload_len == 126) {
        if (!tls_read_exact(tls, raw_head + 2, 2)) return 0;
        payload_len = (unsigned char)raw_head[2] << 8 | (unsigned char)raw_head[3];
    }
    if (payload_len < expected_len) return 0;
    if (!tls_read_exact(tls, out_buf, payload_len)) return 0;
    return payload_len;
}
