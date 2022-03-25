/*
 * Copyright (c) 2017, 2021 ADLINK Technology Inc.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
 *
 * Contributors:
 *   ADLINK zenoh team, <zenoh@adlink-labs.tech>
 */

#ifndef ZENOH_PICO_SYSTEM_LINK_UDP_H
#define ZENOH_PICO_SYSTEM_LINK_UDP_H

#include <stdint.h>
#include "zenoh-pico/collections/string.h"

#if Z_LINK_UDP_UNICAST == 1 || Z_LINK_UDP_MULTICAST == 1

typedef struct
{
    int sock;
    int msock;
    void *raddr;
    void *laddr;
} _z_udp_socket_t;

void *_z_create_endpoint_udp(const _z_str_t s_addr, const _z_str_t port);
void _z_free_endpoint_udp(void *arg);

// Unicast
int _z_open_udp_unicast(void *arg, const clock_t tout);
int _z_listen_udp_unicast(void *arg, const clock_t tout);
void _z_close_udp_unicast(int sock);
size_t _z_read_exact_udp_unicast(int sock, uint8_t *ptr, size_t len);
size_t _z_read_udp_unicast(int sock, uint8_t *ptr, size_t len);
size_t _z_send_udp_unicast(int sock, const uint8_t *ptr, size_t len, void *arg);

// Multicast
int _z_open_udp_multicast(void *arg_1, void **arg_2, const clock_t tout, const _z_str_t iface);
int _z_listen_udp_multicast(void *arg, const clock_t tout, const _z_str_t iface);
void _z_close_udp_multicast(int sock_recv, int sock_send, void *arg);
size_t _z_read_exact_udp_multicast(int sock, uint8_t *ptr, size_t len, void *arg, _z_bytes_t *addr);
size_t _z_read_udp_multicast(int sock, uint8_t *ptr, size_t len, void *arg, _z_bytes_t *addr);
size_t _z_send_udp_multicast(int sock, const uint8_t *ptr, size_t len, void *arg);
#endif

#endif /* ZENOH_PICO_SYSTEM_LINK_UDP_H */
