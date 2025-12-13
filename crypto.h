#ifndef CRYPTO_H
#define CRYPTO_H

#include <winsock2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "common.h" // [修复] 引入 common.h 以使用其中定义的 TLSContext

// [修复] 删除此处重复定义的 TLSContext
// typedef struct {
//     SOCKET sock;
//     SSL *ssl;
// } TLSContext;

extern SSL_CTX *g_ssl_ctx;

void init_openssl_global();
void FreeGlobalSSLContext();

// mode: 0=默认(温和), 1=强力(自动重试)
int tls_init_connect(TLSContext *ctx, int mode);

int tls_write(TLSContext *ctx, const char *data, int len);
int tls_read(TLSContext *ctx, char *out, int max);
int tls_read_exact(TLSContext *ctx, char *buf, int len);
void tls_close(TLSContext *ctx);

int build_ws_frame(const char *in, int len, char *out);
int check_ws_frame(unsigned char *in, int len, int *head_len, int *payload_len);
int ws_read_payload_exact(TLSContext *tls, char *out_buf, int expected_len);

#endif
