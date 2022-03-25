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

#include "zenoh-pico/protocol/msgcodec.h"
#include "zenoh-pico/protocol/utils.h"
#include "zenoh-pico/session/query.h"
#include "zenoh-pico/session/queryable.h"
#include "zenoh-pico/session/resource.h"
#include "zenoh-pico/session/subscription.h"
#include "zenoh-pico/utils/logging.h"

/*------------------ Handle message ------------------*/
int _z_handle_zenoh_message(_z_session_t *zn, _z_zenoh_message_t *msg)
{
    switch (_Z_MID(msg->header))
    {
    case _Z_MID_DATA:
    {
        _Z_INFO("Received _Z_MID_DATA message %d\n", msg->header);
        if (msg->reply_context) // This is some data from a query
            _z_trigger_query_reply_partial(zn, msg->reply_context, msg->body.data.key, msg->body.data.payload, msg->body.data.info);
        else // This is pure data
            _z_trigger_subscriptions(zn, msg->body.data.key, msg->body.data.payload, msg->body.data.info.encoding);

        return _Z_RES_OK;
    }

    case _Z_MID_DECLARE:
    {
        _Z_INFO("Received _Z_DECLARE message\n");
        for (unsigned int i = 0; i < msg->body.declare.declarations.len; i++)
        {
            _z_declaration_t decl = msg->body.declare.declarations.val[i];
            switch (_Z_MID(decl.header))
            {
            case _Z_DECL_RESOURCE:
            {
                _Z_INFO("Received declare-resource message\n");

                _z_zint_t id = decl.body.res.id;
                _z_reskey_t key = decl.body.res.key;

                // Register remote resource declaration
                _z_resource_t *r = (_z_resource_t *)malloc(sizeof(_z_resource_t));
                r->id = id;
                r->key.rid = key.rid;
                r->key.rname = _z_str_clone(key.rname);

                int res = _z_register_resource(zn, _Z_RESOURCE_REMOTE, r);
                if (res != 0)
                {
                    _z_resource_clear(r);
                    free(r);
                }

                break;
            }

            case _Z_DECL_PUBLISHER:
            {
                _Z_INFO("Received declare-publisher message\n");
                // TODO: not supported yet
                break;
            }

            case _Z_DECL_SUBSCRIBER:
            {
                _Z_INFO("Received declare-subscriber message\n");
                _z_str_t rname = _z_get_resource_name_from_key(zn, _Z_RESOURCE_REMOTE, &decl.body.sub.key);

                _z_subscriber_list_t *subs = _z_get_subscriptions_by_name(zn, _Z_RESOURCE_REMOTE, rname);
                if (subs != NULL)
                {
                    _z_str_clear(rname);
                    break;
                }

                _z_subscriber_t *rs = (_z_subscriber_t *)malloc(sizeof(_z_subscriber_t));
                rs->id = _z_get_entity_id(zn);
                rs->rname = rname;
                rs->key = _z_reskey_duplicate(&decl.body.sub.key);
                rs->info = decl.body.sub.subinfo;
                rs->callback = NULL;
                rs->arg = NULL;
                _z_register_subscription(zn, _Z_RESOURCE_REMOTE, rs);

                _z_list_free(&subs, _z_noop_free);
                break;
            }
            case _Z_DECL_QUERYABLE:
            {
                _Z_INFO("Received declare-queryable message\n");
                // TODO: not supported yet
                break;
            }
            case _Z_DECL_FORGET_RESOURCE:
            {
                _Z_INFO("Received forget-resource message\n");
                _z_resource_t *rd = _z_get_resource_by_id(zn, _Z_RESOURCE_REMOTE, decl.body.forget_res.rid);
                if (rd != NULL)
                    _z_unregister_resource(zn, _Z_RESOURCE_REMOTE, rd);

                break;
            }
            case _Z_DECL_FORGET_PUBLISHER:
            {
                _Z_INFO("Received forget-publisher message\n");
                // TODO: not supported yet
                break;
            }
            case _Z_DECL_FORGET_SUBSCRIBER:
            {
                _Z_INFO("Received forget-subscriber message\n");
                _z_subscriber_list_t *subs = _z_get_subscription_by_key(zn, _Z_RESOURCE_REMOTE, &decl.body.forget_sub.key);

                _z_subscriber_list_t *xs = subs;
                while (xs != NULL)
                {
                    _z_subscriber_t *sub = _z_subscriber_list_head(xs);
                    _z_unregister_subscription(zn, _Z_RESOURCE_REMOTE, sub);
                    xs = _z_subscriber_list_tail(xs);
                }
                _z_list_free(&subs, _z_noop_free);
                break;
            }
            case _Z_DECL_FORGET_QUERYABLE:
            {
                _Z_INFO("Received forget-queryable message\n");
                // TODO: not supported yet
                break;
            }
            default:
            {
                _Z_INFO("Unknown declaration message ID");
                return _Z_RES_ERR;
            }
            }
        }

        return _Z_RES_OK;
    }

    case _Z_MID_PULL:
    {
        _Z_INFO("Received _Z_PULL message\n");
        // TODO: not supported yet
        return _Z_RES_OK;
    }

    case _Z_MID_QUERY:
    {
        _Z_INFO("Received _Z_QUERY message\n");
        _z_trigger_queryables(zn, &msg->body.query);
        return _Z_RES_OK;
    }

    case _Z_MID_UNIT:
    {
        _Z_INFO("Received _Z_UNIT message\n");
        // This might be the final reply
        if (msg->reply_context)
            _z_trigger_query_reply_final(zn, msg->reply_context);

        return _Z_RES_OK;
    }

    default:
    {
        _Z_ERROR("Unknown zenoh message ID\n");
        return _Z_RES_ERR;
    }
    }
}
