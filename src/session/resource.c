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

#include "zenoh-pico/session/resource.h"
#include "zenoh-pico/utils/logging.h"

int _z_resource_eq(const _z_resource_t *other, const _z_resource_t *this)
{
    return this->id == other->id;
}

void _z_resource_clear(_z_resource_t *res)
{
    _z_reskey_clear(&res->key);
}

/*------------------ Entity ------------------*/
_z_zint_t _z_get_entity_id(_z_session_t *zn)
{
    return zn->entity_id++;
}

_z_zint_t _z_get_resource_id(_z_session_t *zn)
{
    return zn->resource_id++;
}

/*------------------ Resource ------------------*/
_z_resource_t *__z_get_resource_by_id(_z_resource_list_t *xs, const _z_zint_t id)
{
    while (xs != NULL)
    {
        _z_resource_t *r = _z_resource_list_head(xs);
        if (r->id == id)
            return r;

        xs = _z_resource_list_tail(xs);
    }

    return NULL;
}

_z_resource_t *__z_get_resource_by_key(_z_resource_list_t *xs, const _z_reskey_t *reskey)
{
    while (xs != NULL)
    {
        _z_resource_t *r = _z_resource_list_head(xs);
        if (r->key.rid == reskey->rid && _z_str_eq(r->key.rname, reskey->rname) == 1)
            return r;

        xs = _z_resource_list_tail(xs);
    }

    return NULL;
}

_z_str_t __z_get_resource_name_from_key(_z_resource_list_t *xs, const _z_reskey_t *reskey)
{
    // Need to build the complete resource name, by recursively look at RIDs
    // Resource names are looked up from right to left
    _z_str_list_t *strs = NULL;
    size_t len = 0;

    // Append suffix as the right-most segment
    if (reskey->rname != NULL)
    {
        len += strlen(reskey->rname);
        strs = _z_str_list_push(strs, reskey->rname);
    }

    // Recursevely go through all the RIDs
    _z_zint_t id = reskey->rid;
    while (id != Z_RESOURCE_ID_NONE)
    {
        _z_resource_t *res = __z_get_resource_by_id(xs, id);
        if (res == NULL)
            goto ERR;

        if (res->key.rname != NULL)
        {
            len += strlen(res->key.rname);
            strs = _z_str_list_push(strs, res->key.rname);
        }

        id = res->key.rid;
    }

    // Concatenate all the partial resource names
    _z_str_t rname = (_z_str_t)malloc(len + 1);
    rname[0] = '\0'; // NULL terminator must be set (required to strcat)

    _z_str_list_t *xstr = strs;
    while (xstr != NULL)
    {
        _z_str_t s = _z_str_list_head(xstr);
        strcat(rname, s);
        xstr = _z_str_list_tail(xstr);
    }

    _z_list_free(&strs, _z_noop_free);
    return rname;

ERR:
    _z_list_free(&strs, _z_noop_free);
    return NULL;
}

/**
 * This function is unsafe because it operates in potentially concurrent data.
 * Make sure that the following mutexes are locked before calling this function:
 *  - zn->mutex_inner
 */
_z_resource_t *__unsafe_z_get_resource_by_id(_z_session_t *zn, int is_local, _z_zint_t id)
{
    _z_resource_list_t *decls = is_local ? zn->local_resources : zn->remote_resources;
    return __z_get_resource_by_id(decls, id);
}

/**
 * This function is unsafe because it operates in potentially concurrent data.
 * Make sure that the following mutexes are locked before calling this function:
 *  - zn->mutex_inner
 */
_z_resource_t *__unsafe_z_get_resource_by_key(_z_session_t *zn, int is_local, const _z_reskey_t *reskey)
{
    _z_resource_list_t *decls = is_local ? zn->local_resources : zn->remote_resources;
    return __z_get_resource_by_key(decls, reskey);
}

/**
 * This function is unsafe because it operates in potentially concurrent data.
 * Make sure that the following mutexes are locked before calling this function:
 *  - zn->mutex_inner
 */
_z_str_t __unsafe_z_get_resource_name_from_key(_z_session_t *zn, int is_local, const _z_reskey_t *reskey)
{
    _z_resource_list_t *decls = is_local ? zn->local_resources : zn->remote_resources;
    return __z_get_resource_name_from_key(decls, reskey);
}

_z_resource_t *_z_get_resource_by_id(_z_session_t *zn, int is_local, _z_zint_t rid)
{
    _z_mutex_lock(&zn->mutex_inner);
    _z_resource_t *res = __unsafe_z_get_resource_by_id(zn, is_local, rid);
    _z_mutex_unlock(&zn->mutex_inner);
    return res;
}

_z_resource_t *_z_get_resource_by_key(_z_session_t *zn, int is_local, const _z_reskey_t *reskey)
{
    _z_mutex_lock(&zn->mutex_inner);
    _z_resource_t *res = __unsafe_z_get_resource_by_key(zn, is_local, reskey);
    _z_mutex_unlock(&zn->mutex_inner);
    return res;
}

_z_str_t _z_get_resource_name_from_key(_z_session_t *zn, int is_local, const _z_reskey_t *reskey)
{
    _z_mutex_lock(&zn->mutex_inner);
    _z_str_t res = __unsafe_z_get_resource_name_from_key(zn, is_local, reskey);
    _z_mutex_unlock(&zn->mutex_inner);
    return res;
}

int _z_register_resource(_z_session_t *zn, int is_local, _z_resource_t *res)
{
    _Z_DEBUG(">>> Allocating res decl for (%zu,%lu,%s)\n", res->id, res->key.rid, res->key.rname);
    _z_mutex_lock(&zn->mutex_inner);

    _z_resource_t *r = __unsafe_z_get_resource_by_id(zn, is_local, res->id);
    if (r != NULL) // Inconsistent declarations have been found
        goto ERR;

    // Register the resource
    if (is_local)
        zn->local_resources = _z_resource_list_push(zn->local_resources, res);
    else
        zn->remote_resources = _z_resource_list_push(zn->remote_resources, res);

    _z_mutex_unlock(&zn->mutex_inner);
    return 0;

ERR:
    _z_mutex_unlock(&zn->mutex_inner);
    return -1;
}

void _z_unregister_resource(_z_session_t *zn, int is_local, _z_resource_t *res)
{
    _z_mutex_lock(&zn->mutex_inner);

    if (is_local)
        zn->local_resources = _z_resource_list_drop_filter(zn->local_resources, _z_resource_eq, res);
    else
        zn->remote_resources = _z_resource_list_drop_filter(zn->remote_resources, _z_resource_eq, res);

    _z_mutex_unlock(&zn->mutex_inner);
}

void _z_flush_resources(_z_session_t *zn)
{
    _z_mutex_lock(&zn->mutex_inner);

    _z_resource_list_free(&zn->local_resources);
    _z_resource_list_free(&zn->remote_resources);

    _z_mutex_unlock(&zn->mutex_inner);
}
