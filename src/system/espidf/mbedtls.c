#include <netdb.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "zenoh-pico/collections/bytes.h"
#include "zenoh-pico/collections/string.h"
#include "zenoh-pico/config.h"
#include "zenoh-pico/system/link/bt.h"
#include "zenoh-pico/system/platform.h"
#include "zenoh-pico/utils/logging.h"
#include "zenoh-pico/utils/pointers.h"

// https://github.com/clarkimusmax/c_examples/blob/a2d597c942e554122cdbb29d6fce7cc00a167794/mbed_tls_verify_certs/tls_client.c


/* mbedtls headers */
#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"

#if Z_LINK_TCP_TLS == 1

static mbedtls_net_context s;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_ssl_context ssl;
static mbedtls_ssl_config conf;
static mbedtls_x509_crt ca;
static mbedtls_x509_crt client;
static mbedtls_pk_context pkey;
char *server = NULL;
char *port = NULL;

#define RESP_BUF_SIZE 2048
#define MBEDTLS_ERROR_BUFFER_SIZE 128

static void debug_handler(void *ctx, int level, const char *file, int line, const char *str)
{
	fprintf((FILE*) ctx, "%s:%d: [%d] %s", file, line, level, str);
	fflush((FILE*) ctx);
}

void get_server_tls(const char *s_addr, const char *s_port)
{
    server = (char *)malloc(sizeof(s_addr));
    memcpy(server, s_addr, (sizeof(s_addr)));
    port = (char *)malloc(sizeof(s_port));
    memcpy(server, s_port, (sizeof(s_port)));
}

static void exit_tls(void)
{
	mbedtls_x509_crt_free(&ca);
	mbedtls_x509_crt_free(&client);
	mbedtls_net_free(&s);
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
    if (server != NULL)
        free(server);
    if (port != NULL)
        free(port);
}

static int8_t setup_tls(void)
{
    int ret = 0;

#ifndef Z_TLS_CERT
#error "TLS certificate not defined"
#endif

#ifndef Z_TLS_KEY
#error "TLS key not defined"
#endif

    mbedtls_net_init(&s);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	mbedtls_x509_crt_init(&ca);
	mbedtls_x509_crt_init(&client);
	mbedtls_pk_init(&pkey);

	/* Load CA & client certs */
    ret = mbedtls_x509_crt_parse_file(&ca, Z_TLS_CERT);
	if (ret) {
		_Z_ERROR("mbedtls_x509_crt_parse_file failed (%d)\n", ret);
        exit_tls();
		return ret;
	}

	/* Load client key */
    ret = mbedtls_pk_parse_keyfile(&pkey, Z_TLS_KEY , NULL);
	if (ret) {
		_Z_ERROR("mbedtls_pk_parse_keyfile failed (%d)\n", ret);
        exit_tls();
		return ret;
	}

	/* Seed PRNG */
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
	if (ret) {
		_Z_ERROR("mbedtls_ctr_drbg_seed failed (%d)\n", ret);
        exit_tls();
		return ret;
	}

	/* Get SSL config defaults */
    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, 
        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret) {
		_Z_ERROR("mbedtls_ssl_config_defaults failed (%d)\n", ret);
        exit_tls();
		return ret;
	}

	/* Set client cert */
    ret = mbedtls_ssl_conf_own_cert(&conf, &client, &pkey);
	if (ret) {
		_Z_ERROR("mbedtls_ssl_own_cert failed (%d)\n", ret);
        exit_tls();
		return ret;
	}

	/* Require cert verification */
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);

	/* 
	 * Add CA chain to SSL config, with 3rd param (Certificate Revocation
	 * List) ignored
	 */
	mbedtls_ssl_conf_ca_chain(&conf, &ca, NULL);
	
	/* Set PRNG and debug functions */
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_dbg(&conf, debug_handler, stderr);

	/* Setup SSL */
    ret = mbedtls_ssl_setup(&ssl, &conf);
	if (ret) {
		_Z_ERROR("mbedtls_ssl_setup failed (%d)\n", ret);
        exit_tls();
		return ret;
	}

	return ret;
}

int8_t open_tcp_tls(int *fd)
{
    int8_t ret = _Z_RES_OK;
    char mbedtls_error[MBEDTLS_ERROR_BUFFER_SIZE];

    ret = setup_tls();
    if (ret)
        return ret;

    ret = mbedtls_net_connect(&s, server, port, MBEDTLS_NET_PROTO_TCP);
    if (ret) {
        _Z_ERROR("mbedtls_net_connect failed (%d)\n", ret);
    } else {
        fd = &s.fd;
    }

	/* Set TCP socket I/O functions to mbedtls_net_send/recv */
	mbedtls_ssl_set_bio(&ssl, &s, mbedtls_net_send, mbedtls_net_recv, NULL);

	/* SSL Handshake */
	while((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
		if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			mbedtls_strerror(ret, mbedtls_error, MBEDTLS_ERROR_BUFFER_SIZE);
			_Z_ERROR("mbedtls_ssl_handshake failed: %s\n", mbedtls_error);
		}
	}

    return ret;
}

size_t send_tcp_tls(const uint8_t *ptr, size_t len)
{
	int ret = 1;

    while ((ret = mbedtls_ssl_write(&ssl, ptr, len)) <= 0) {
        if (ret) {
            _Z_ERROR("write failed (%d)\n", ret);
        }
    }
}

ssize_t rcv_tcp_tls(uint8_t *ptr, size_t len)
{
    return mbedtls_ssl_read(&ssl, ptr, len);
}

void close_tcp_tls(void)
{
	mbedtls_ssl_close_notify(&ssl);
    exit_tls();
}

#endif // Z_LINK_TCP_TLS
