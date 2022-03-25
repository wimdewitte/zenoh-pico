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

#include <stdio.h>
#include <assert.h>
#include "zenoh-pico.h"
#include "zenoh-pico/system/platform.h"

#define MSG 1000
#define MSG_LEN 1024
#define QRY 100
#define QRY_CLT 10
#define SET 100
#define SLEEP 1
#define TIMEOUT 60

_z_str_t uri = "/demo/example/";
unsigned int idx[SET];

// The active resource, subscriber, queryable declarations
_z_list_t *pubs1 = NULL; // @TODO: use type-safe list
unsigned long rids1[SET];

_z_list_t *subs2 = NULL; // @TODO: use type-safe list
_z_list_t *qles2 = NULL; // @TODO: use type-safe list
unsigned long rids2[SET];

volatile unsigned int total = 0;

volatile unsigned int queries = 0;
void query_handler(const z_query_t *query, const void *arg)
{
    char res[64];
    sprintf(res, "%s%u", uri, *(unsigned int *)arg);
    printf(">> Received query: %s\t(%u/%u)\n", res, queries, total);
    assert(_z_str_eq(query->rname, res));
    assert(_z_str_eq(query->predicate, ""));

    _z_send_reply(query, res, (const uint8_t *)res, strlen(res));

    queries++;
}

volatile unsigned int replies = 0;
void reply_handler(const _z_reply_t reply, const void *arg)
{
    char res[64];
    sprintf(res, "%s%u", uri, *(unsigned int *)arg);

    if (reply.tag == Z_REPLY_TAG_DATA)
    {
        printf(">> Received reply data: %s %s\t(%u/%u)\n", res, reply.data.data.key.rname, replies, total);
        assert(reply.data.data.value.len == strlen(res));
        assert(strncmp(res, (const _z_str_t)reply.data.data.value.val, strlen(res)) == 0);
        assert(strlen(reply.data.data.key.rname) == strlen(res));
        assert(strncmp(res, reply.data.data.key.rname, strlen(res)) == 0);
    }
    else
    {
        replies++;
        printf(">> Received reply final: %s\t(%u/%u)\n", res, replies, total);
    }
}

volatile unsigned int datas = 0;
void data_handler(const _z_sample_t *sample, const void *arg)
{
    char res[64];
    sprintf(res, "%s%u", uri, *(unsigned int *)arg);
    printf(">> Received data: %s\t(%u/%u)\n", res, datas, total);

    assert(sample->value.len == MSG_LEN);
    assert(strlen(sample->key.rname) == strlen(res));
    assert(strncmp(res, sample->key.rname, strlen(res)) == 0);
    (void) (sample);

    datas++;
}

int main(int argc, _z_str_t *argv)
{
    assert(argc == 2);
    (void) (argc);

    setbuf(stdout, NULL);

    _z_properties_t *config = _z_properties_default();
    _z_properties_insert(config, Z_CONFIG_PEER_KEY, z_string_make(argv[1]));
    int is_reliable = strncmp(argv[1], "tcp", 3) == 0;

    for (unsigned int i = 0; i < SET; i++)
        idx[i] = i;

    _z_session_t *s1 = _z_open(config);
    assert(s1 != NULL);
    _z_string_t pid1 = _z_string_from_bytes(&s1->tp_manager->local_pid);
    printf("Session 1 with PID: %s\n", pid1.val);
    _z_string_clear(&pid1);

    // Start the read session session lease loops
    _zp_start_read_task(s1);
    _zp_start_lease_task(s1);

    _z_sleep_s(SLEEP);

    _z_session_t *s2 = _z_open(config);
    assert(s2 != NULL);
    _z_string_t pid2 = _z_string_from_bytes(&s2->tp_manager->local_pid);
    printf("Session 2 with PID: %s\n", pid2.val);
    _z_string_clear(&pid2);

    // Start the read session session lease loops
    _zp_start_read_task(s2);
    _zp_start_lease_task(s2);

    _z_sleep_s(SLEEP);

    // Declare resources on both sessions
    char s1_res[64];
    for (unsigned int i = 0; i < SET; i++)
    {
        sprintf(s1_res, "%s%d", uri, i);
        _z_reskey_t rk = _z_rname(s1_res);
        unsigned long rid = _z_declare_resource(s1, rk);
        printf("Declared resource on session 1: %lu %lu %s\n", rid, rk.rid, rk.rname);
        rids1[i] = rid;
    }

    _z_sleep_s(SLEEP);

    for (unsigned int i = 0; i < SET; i++)
    {
        sprintf(s1_res, "%s%d", uri, i);
        _z_reskey_t rk = _z_rname(s1_res);
        unsigned long rid = _z_declare_resource(s2, rk);
        printf("Declared resource on session 2: %lu %lu %s\n", rid, rk.rid, rk.rname);
        rids2[i] = rid;
    }

    _z_sleep_s(SLEEP);

    // Declare subscribers and queryabales on second session
    for (unsigned int i = 0; i < SET; i++)
    {
        _z_reskey_t rk = _z_rid(rids2[i]);
        z_subscriber_t *sub = _z_declare_subscriber(s2, rk, _z_subinfo_default(), data_handler, &idx[i]);
        assert(sub != NULL);
        printf("Declared subscription on session 2: %zu %lu %s\n", sub->id, rk.rid, rk.rname);
        subs2 = _z_list_push(subs2, sub); // @TODO: use type-safe list
    }

    _z_sleep_s(SLEEP);

    for (unsigned int i = 0; i < SET; i++)
    {
        sprintf(s1_res, "%s%d", uri, i);
        _z_reskey_t rk = _z_rname(s1_res);
        z_queryable_t *qle = _z_declare_queryable(s2, rk, Z_QUERYABLE_EVAL, query_handler, &idx[i]);
        assert(qle != NULL);
        printf("Declared queryable on session 2: %zu %lu %s\n", qle->id, rk.rid, rk.rname);
        qles2 = _z_list_push(qles2, qle); // @TODO: use type-safe list
    }

    _z_sleep_s(SLEEP);

    // Declare publisher on firt session
    for (unsigned int i = 0; i < SET; i++)
    {
        _z_reskey_t rk = _z_rid(rids1[i]);
        z_publisher_t *pub = _z_declare_publisher(s1, rk);
        assert(pub != NULL);
        printf("Declared publisher on session 1: %zu\n", pub->id);
        pubs1 = _z_list_push(pubs1, pub); // @TODO: use type-safe list
    }

    _z_sleep_s(SLEEP);

    // Write data from firt session
    size_t len = MSG_LEN;
    const uint8_t *payload = (uint8_t *)malloc(len * sizeof(uint8_t));
    memset((uint8_t *)payload, 1, MSG_LEN);

    total = MSG * SET;
    for (unsigned int n = 0; n < MSG; n++)
    {
        for (unsigned int i = 0; i < SET; i++)
        {
            _z_reskey_t rk = _z_rid(rids1[i]);
            _z_write_ext(s1, rk, payload, len, Z_ENCODING_DEFAULT, Z_DATA_KIND_DEFAULT, Z_CONGESTION_CONTROL_BLOCK);
            printf("Wrote data from session 1: %lu %zu b\t(%u/%u)\n", rk.rid, len, n * SET + (i + 1), total);
        }
    }

    // Wait to receive all the data
    _z_clock_t now = _z_clock_now();
    unsigned int expected = is_reliable ? total : 1;
    while (datas < expected)
    {
        assert(_z_clock_elapsed_s(&now) < TIMEOUT);
        printf("Waiting for datas... %u/%u\n", datas, expected);
        _z_sleep_s(SLEEP);
    }
    if (is_reliable)
        assert(datas == expected);
    else
        assert(datas >= expected);
    datas = 0;

    _z_sleep_s(SLEEP);

    // Query data from first session
    total = QRY * SET;
    for (unsigned int n = 0; n < QRY; n++)
    {
        for (unsigned int i = 0; i < SET; i++)
        {
            sprintf(s1_res, "%s%d", uri, i);
            _z_reskey_t rk = _z_rname(s1_res);
            _z_query_target_t qry_tgt = _z_query_target_default();
            _z_consolidation_strategy_t qry_con = _z_consolidation_strategy_default();
            _z_query(s1, rk, "", qry_tgt, qry_con, reply_handler, &idx[i]);
            printf("Queried data from session 1: %lu %s\n", rk.rid, rk.rname);
        }
    }

    // Wait to receive all the expected queries
    now = _z_clock_now();
    expected = is_reliable ? total : 1;
    while (queries < expected)
    {
        assert(_z_clock_elapsed_s(&now) < TIMEOUT);
        printf("Waiting for queries... %u/%u\n", queries, expected);
        _z_sleep_s(SLEEP);
    }
    if (is_reliable)
        assert(queries == expected);
    else
        assert(queries >= expected);
    queries = 0;

    // Wait to receive all the expectred replies
    now = _z_clock_now();
    while (replies < expected)
    {
        assert(_z_clock_elapsed_s(&now) < TIMEOUT);
        printf("Waiting for replies... %u/%u\n", replies, expected);
        _z_sleep_s(SLEEP);
    }
    if (is_reliable)
        assert(replies == expected);
    else
        assert(replies >= expected);
    replies = 0;

    if (is_reliable)
    {
        _z_sleep_s(SLEEP);

        // Query and collect from first session
        total = QRY_CLT * SET;
        for (unsigned int n = 0; n < QRY_CLT; n++)
        {
            for (unsigned int i = 0; i < SET; i++)
            {
                sprintf(s1_res, "%s%d", uri, i);
                _z_reskey_t rk = _z_rname(s1_res);
                _z_reskey_t myrk = _z_rname(s1_res);
                _z_query_target_t qry_tgt = _z_query_target_default();
                _z_consolidation_strategy_t qry_con = _z_consolidation_strategy_default();
                _z_reply_data_array_t ra = _z_query_collect(s1, myrk, "", qry_tgt, qry_con);
                printf("Queried and collected data from session 1: %lu %s\n", rk.rid, rk.rname);
                _z_reskey_clear(&rk);
                replies += ra.len;
                _z_reply_data_array_clear(&ra);
            }
        }
        assert(replies == total);
    }

    _z_sleep_s(SLEEP);

    // Undeclare publishers on first session
    while (pubs1)
    {
        z_publisher_t *pub = _z_list_head(pubs1); // @TODO: use type-safe list
        printf("Undeclared publisher on session 2: %zu\n", pub->id);
        _z_undeclare_publisher(pub);
        pubs1 = _z_list_pop(pubs1, _z_noop_elem_free); // @TODO: use type-safe list
    }

    _z_sleep_s(SLEEP);

    // Undeclare subscribers and queryables on second session
    while (subs2)
    {
        z_subscriber_t *sub = _z_list_head(subs2); // @TODO: use type-safe list
        printf("Undeclared subscriber on session 2: %zu\n", sub->id);
        _z_undeclare_subscriber(sub);
        subs2 = _z_list_pop(subs2, _z_noop_elem_free); // @TODO: use type-safe list
    }

    _z_sleep_s(SLEEP);

    while (qles2)
    {
        z_queryable_t *qle = _z_list_head(qles2); // @TODO: use type-safe list
        printf("Undeclared queryable on session 2: %zu\n", qle->id);
        _z_undeclare_queryable(qle);
        qles2 = _z_list_pop(qles2, _z_noop_elem_free); // @TODO: use type-safe list
    }

    _z_sleep_s(SLEEP);

    // Undeclare resources on both sessions
    for (unsigned int i = 0; i < SET; i++)
    {
        printf("Undeclared resource on session 1: %lu\n", rids1[i]);
        _z_undeclare_resource(s1, rids1[i]);
    }

    _z_sleep_s(SLEEP);

    for (unsigned int i = 0; i < SET; i++)
    {
        printf("Undeclared resource on session 2: %lu\n", rids2[i]);
        _z_undeclare_resource(s2, rids2[i]);
    }

    _z_sleep_s(SLEEP);

    // Stop both sessions
    printf("Stopping threads on session 1\n");
    _zp_stop_lease_task(s1);
    _zp_stop_read_task(s1);

    printf("Stopping threads on session 2\n");
    _zp_stop_lease_task(s2);
    _zp_stop_read_task(s2);

    // Close both sessions
    printf("Closing session 1\n");
    _z_close(s1);

    _z_sleep_s(SLEEP);

    printf("Closing session 2\n");
    _z_close(s2);

    // Cleanup properties
    _z_properties_free(&config);

    free((uint8_t *)payload);
    payload = NULL;

    return 0;
}
