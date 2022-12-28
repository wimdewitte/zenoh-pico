#ifndef ZENOH_PICO_SYSTEM_ESPIDF_MBEDTLS_H
#define ZENOH_PICO_SYSTEM_ESPIDF_MBEDTLS_H

#include <stdint.h>

void get_server_tls(const char *s_addr, const char *s_port);
int8_t open_tcp_tls(int *fd);
void close_tcp_tls(void);
size_t send_tcp_tls(const uint8_t *ptr, size_t len);
ssize_t rcv_tcp_tls(uint8_t *ptr, size_t len);

#endif /* ZENOH_PICO_SYSTEM_ESPIDF_MBEDTLS_H */
