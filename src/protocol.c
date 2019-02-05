/* BSD 2-Clause License
 *
 * Copyright (c) 2018, Andrea Giacomo Baldan All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include "util.h"
#include "protocol.h"


/*
 * Conversion table for request, maps OPCODE -> COMMAND_TYPE, it's still a
 * shitty abstraction, further improvements planned on future refactoring
 */
static const uint8_t opcode_req_map[COMMAND_COUNT][2] = {
    {ACK, EMPTY_COMMAND},
    {PUT, KEY_VAL_COMMAND},
    {GET, KEY_COMMAND},
    {DEL, KEY_LIST_COMMAND},
    {TTL, KEY_COMMAND},
    {INC, KEY_LIST_COMMAND},
    {DEC, KEY_LIST_COMMAND},
    {COUNT, KEY_COMMAND},
    {KEYS, KEY_COMMAND},
    {USE, KEY_COMMAND},
    {CLUSTER_JOIN, KEY_VAL_COMMAND},
    {CLUSTER_MEMBERS, KEY_VAL_LIST_COMMAND},
    {PING, EMPTY_COMMAND},
    {DB, EMPTY_COMMAND},
    {INFO, EMPTY_COMMAND},
    {QUIT, EMPTY_COMMAND}
};

/*
 * Conversion table for response, maps OPCODE -> CONTENT_TYPE, it's still a
 * shitty abstraction, further improvements planned on future refactoring
 */
static const uint8_t opcode_res_map[9][2] = {
    {ACK, EMPTY_PAYLOAD},
    {GET, DATA_PAYLOAD},
    {DEL, EMPTY_PAYLOAD},
    {TTL, EMPTY_PAYLOAD},
    {INC, EMPTY_PAYLOAD},
    {DEC, EMPTY_PAYLOAD},
    {COUNT, VALUE_PAYLOAD},
    {KEYS, LIST_PAYLOAD},
    {CLUSTER_MEMBERS, KVLIST_PAYLOAD}
};


static void pack_header(const struct header *, struct buffer *);
static void unpack_header(struct buffer *, struct header *);
static void free_header(struct header *);
static struct command *unpack_command(struct buffer *, struct header *);
static void free_command_header(struct command *);
static void free_command(struct command *, bool);
static void header_init(struct header *, uint8_t, uint32_t, uint8_t, const char *);
static int8_t get_command_type(uint8_t);
static int8_t get_content_type(uint8_t);


static int8_t get_command_type(uint8_t opcode) {

    int ctype = -1;

    for (int i = 0; i < COMMAND_COUNT && ctype == -1; i++)
        if (opcode_req_map[i][0] == opcode)
            ctype = opcode_req_map[i][1];

    return ctype;
}


static int8_t get_content_type(uint8_t opcode) {

    int cctype = -1;

    for (int i = 0; i < 9 && cctype == -1; i++)
        if (opcode_res_map[i][0] == opcode)
            cctype = opcode_res_map[i][1];

    return cctype;
}


static void pack_header(const struct header *hdr, struct buffer *buf) {

    assert(buf && hdr);

    pack(buf, "BIB", hdr->opcode, buf->size, hdr->flags);

    if ((hdr->flags & F_FROMNODEREQUEST) || (hdr->flags & F_FROMNODERESPONSE))
        pack(buf, "s", hdr->transaction_id);

}


static void unpack_header(struct buffer *buf, struct header *hdr) {

    assert(buf && hdr);

    unpack(buf, "BIB", &hdr->opcode, &hdr->size, &hdr->flags);

    if (hdr->flags & F_FROMNODEREQUEST || hdr->flags & F_FROMNODERESPONSE) {
        const char transaction_id[UUID_LEN];
        char fmt[4];
        snprintf(fmt, 4, "%ds", UUID_LEN - 1);
        unpack(buf, fmt, transaction_id);
        strcpy(hdr->transaction_id, transaction_id);
    }
}


static void free_header(struct header *hdr) {
    tfree(hdr);
}


static void free_command_header(struct command *cmd) {

    if (!cmd)
        return;

    switch (cmd->cmdtype) {
        case EMPTY_COMMAND:
            free_header(cmd->e_cmd->hdr);
            break;
        case KEY_COMMAND:
            free_header(cmd->k_cmd->hdr);
            break;
        case KEY_VAL_COMMAND:
            free_header(cmd->kv_cmd->hdr);
            break;
        case KEY_LIST_COMMAND:
            free_header(cmd->kl_cmd->hdr);
            break;
    }
}


static void free_command(struct command *cmd, bool with_header) {

    if (!cmd)
        return;

    switch (cmd->cmdtype) {
        case EMPTY_COMMAND:
            if (with_header)
                free_header(cmd->e_cmd->hdr);
            tfree(cmd->e_cmd);
            break;
        case KEY_COMMAND:
            if (with_header)
                free_header(cmd->k_cmd->hdr);
            tfree(cmd->k_cmd->key);
            tfree(cmd->k_cmd);
            break;
        case KEY_VAL_COMMAND:
            if (with_header)
                free_header(cmd->kv_cmd->hdr);
            tfree(cmd->kv_cmd->key);
            tfree(cmd->kv_cmd->val);
            tfree(cmd->kv_cmd);
            break;
        case KEY_LIST_COMMAND:
            if (with_header)
                free_header(cmd->kl_cmd->hdr);
            for (int i = 0; i < cmd->kl_cmd->len; i++) {
                tfree(cmd->kl_cmd->keys[i]->key);
                tfree(cmd->kl_cmd->keys[i]);
            }
            tfree(cmd->kl_cmd->keys);
            tfree(cmd->kl_cmd);
            break;
    }

    tfree(cmd);
}


static void header_init(struct header *hdr, uint8_t opcode, uint32_t size,
                        uint8_t flags, const char *transaction_id) {

    hdr->opcode = opcode;
    hdr->size = size;
    hdr->flags = 0 | flags;

    if (transaction_id && (flags & F_FROMNODERESPONSE)) {
        strncpy(hdr->transaction_id,
                (const char *) transaction_id, UUID_LEN - 1);
        hdr->transaction_id[UUID_LEN - 1] = '\0';
        hdr->size += UUID_LEN - 1;
    }
}


/********************************************
 *         REQUEST PACKING FUNCTIONS
 ********************************************/


void pack_request(struct buffer *buf, const struct request *req, int reqtype) {

    assert(buf && req);

    // FIXME make it consistent with the rest
    switch (reqtype) {
        case KEY_COMMAND:
            pack_header(req->cmd->k_cmd->hdr, buf);
            pack_u16(buf, req->cmd->k_cmd->keysize);
            pack_bytes(buf, req->cmd->k_cmd->key);
            pack_u8(buf, req->cmd->k_cmd->is_prefix);
            pack_u16(buf, req->cmd->k_cmd->ttl);
            break;
        case KEY_VAL_COMMAND:
            pack_header(req->cmd->kv_cmd->hdr, buf);
            pack_u16(buf, req->cmd->kv_cmd->keysize);
            pack_u32(buf, req->cmd->kv_cmd->valsize);
            pack_bytes(buf, req->cmd->kv_cmd->key);
            pack_bytes(buf, req->cmd->kv_cmd->val);
            pack_u8(buf, req->cmd->kv_cmd->is_prefix);
            pack_u16(buf, req->cmd->kv_cmd->ttl);
            break;
        case KEY_LIST_COMMAND:
            pack_header(req->cmd->kl_cmd->hdr, buf);
            pack_u32(buf, req->cmd->kl_cmd->len);
            for (int i = 0; i < req->cmd->kl_cmd->len; i++) {
                pack_u16(buf, req->cmd->kl_cmd->keys[i]->keysize);
                pack_bytes(buf, req->cmd->kl_cmd->keys[i]->key);
                pack_u8(buf, req->cmd->kl_cmd->keys[i]->is_prefix);
            }
            break;
        default:
            fprintf(stderr, "Pack request: not implemented yet\n");
            break;
    }
}


struct request *unpack_request(struct buffer *buf) {

    assert(buf);

    struct request *req = tmalloc(sizeof(*req));
    if (!req)
        return NULL;

    struct header *hdr = tmalloc(sizeof(*hdr));
    if (!hdr)
        goto errnomem2;

    unpack_header(buf, hdr);

    if (!(hdr->flags & F_BULKREQUEST)) {
        /* It's a single request, just unpack it into the request pointer */
        req->reqtype = SINGLE_REQUEST;
        req->cmd = unpack_command(buf, hdr);
    } else {
        /*
         * Unpack the bulk request format, a request formed by a list of
         * single requests.
         */
        req->reqtype = BULK_REQUEST;
        req->bulk_cmd = tmalloc(sizeof(struct bulk_command));
        if (!req->bulk_cmd)
            goto errnomem1;

        uint32_t ncommands = unpack_u32(buf);
        req->bulk_cmd->ncommands = ncommands;
        req->bulk_cmd->cmds = tmalloc(ncommands * sizeof(struct command));

        /* Unpack each single packet into the array of requests */
        for (uint32_t i = 0; i < ncommands; i++)
            req->bulk_cmd->cmds[i] = unpack_command(buf, hdr);
    }

    return req;

errnomem1:

    tfree(hdr);

errnomem2:

    tfree(req);
    return NULL;
}

/*
 * Main unpacking function, to translates bytes received from clients in
 * network byte-order (big-endian) to a command structure, based on the opcode
 */
static struct command *unpack_command(struct buffer *buf, struct header *hdr) {

    assert(buf && hdr);

    struct command *cmd = tmalloc(sizeof(*cmd));
    if (!cmd)
        return NULL;

    cmd->cmdtype = get_command_type(hdr->opcode);

    switch (cmd->cmdtype) {
        case EMPTY_COMMAND:
            cmd->e_cmd = tmalloc(sizeof(struct empty_command));
            if (!cmd->e_cmd)
                goto errnomem3;

            cmd->e_cmd->hdr = hdr;
            break;
        case KEY_COMMAND:
            cmd->k_cmd = tmalloc(sizeof(struct key_command));
            if (!cmd->k_cmd)
                goto errnomem3;

            cmd->k_cmd->hdr = hdr;

            // Mandatory fields
            cmd->k_cmd->keysize = unpack_u16(buf);
            cmd->k_cmd->key = unpack_bytes(buf, cmd->k_cmd->keysize);

            // Optional fields
            cmd->k_cmd->is_prefix = unpack_u8(buf);
            cmd->k_cmd->ttl = unpack_u16(buf);

            break;

        case KEY_VAL_COMMAND:
            cmd->kv_cmd = tmalloc(sizeof(struct keyval_command));
            if (!cmd->kv_cmd)
                goto errnomem3;

            cmd->kv_cmd->hdr = hdr;

            // Mandatory fields
            cmd->kv_cmd->keysize = unpack_u16(buf);
            cmd->kv_cmd->valsize = unpack_u32(buf);
            cmd->kv_cmd->key = unpack_bytes(buf, cmd->kv_cmd->keysize);
            cmd->kv_cmd->val = unpack_bytes(buf, cmd->kv_cmd->valsize);

            // Optional fields
            cmd->kv_cmd->is_prefix = unpack_u8(buf);
            cmd->kv_cmd->ttl = unpack_u16(buf);

            break;

        case KEY_LIST_COMMAND:
            cmd->kl_cmd = tmalloc(sizeof(struct key_list_command));
            if (!cmd->kl_cmd)
                goto errnomem3;

            cmd->kl_cmd->hdr = hdr;

            // Number of keys, or length of the Key array
            cmd->kl_cmd->len = unpack_u32(buf);

            cmd->kl_cmd->keys = tcalloc(cmd->kl_cmd->len, sizeof(struct key));

            if (!cmd->kl_cmd->keys)
                goto errnomem2;

            for (int i = 0; i < cmd->kl_cmd->len; i++) {

                struct key *key = tmalloc(sizeof(*key));
                if (!key)
                    goto errnomem1;

                key->keysize = unpack_u16(buf);
                key->key = unpack_bytes(buf, key->keysize);
                key->is_prefix = unpack_u8(buf);
                cmd->kl_cmd->keys[i] = key;
            }

            break;

        default:
            tfree(hdr);
            tfree(cmd);
            break;
    };

    return cmd;

errnomem1:

    tfree(cmd->kl_cmd->keys);

errnomem2:

    tfree(cmd->kl_cmd);

errnomem3:

    tfree(cmd);
    return NULL;
}


void free_request(struct request *req) {

    if (!req)
        return;

    if (req->reqtype == SINGLE_REQUEST) {
        free_command(req->cmd, true);
    } else {

        // FIXME hack, free the first pointer
        free_command_header(req->bulk_cmd->cmds[0]);
        for (int i = 0; i < req->bulk_cmd->ncommands; i++)
            free_command(req->bulk_cmd->cmds[i], false);

        tfree(req->bulk_cmd->cmds);
        tfree(req->bulk_cmd);
    }

    tfree(req);
}

/********************************************
 *             REQUEST HELPERS
 ********************************************/

#define make_cluster_join_request(addr) make_key_request(addr, CLUSTER_JOIN, \
                                                         0x00, 0x00,         \
                                                         F_FROMNODEREQUEST); \


struct request *make_key_request(const uint8_t *key, uint8_t opcode,
                                 uint16_t ttl, uint8_t flags) {

    struct request *req = tmalloc(sizeof(*req));
    if (!req)
        goto err;

    req->reqtype = SINGLE_REQUEST;
    req->cmd = tmalloc(sizeof(struct command));
    if (!req->cmd)
        goto errnomem1;

    req->cmd->cmdtype = KEY_COMMAND;
    req->cmd->k_cmd = tmalloc(sizeof(struct key_command));
    if (!req->cmd->k_cmd)
        goto errnomem2;

    req->cmd->k_cmd->hdr = tmalloc(sizeof(struct header));
    if (!req->cmd->k_cmd->hdr)
        goto errnomem3;

    req->cmd->k_cmd->hdr->size = HEADERLEN + (2 * sizeof(uint16_t))
        + strlen((const char *) key) + sizeof(uint8_t);

    req->cmd->k_cmd->hdr->flags = 0 | flags;

    if (flags & F_FROMNODEREQUEST) {
        char uuid[UUID_LEN];
        generate_uuid(uuid);
        strcpy(req->cmd->k_cmd->hdr->transaction_id, uuid);
        req->cmd->k_cmd->hdr->size += UUID_LEN - 1;
    }

    req->cmd->k_cmd->hdr->opcode = opcode;

    req->cmd->k_cmd->keysize = strlen((const char *) key);
    req->cmd->k_cmd->key = (uint8_t *) tstrdup((const char *) key);

    req->cmd->k_cmd->ttl = ttl;
    req->cmd->k_cmd->is_prefix = flags & F_PREFIXREQUEST ? 1 : 0;

    return req;

errnomem3:

    tfree(req->cmd->k_cmd);

errnomem2:

    tfree(req->cmd);

errnomem1:

    tfree(req);

err:

    return NULL;
}


struct request *make_keyval_request(const uint8_t *key,
                                    const uint8_t *val,
                                    uint8_t opcode,
                                    uint16_t ttl,
                                    uint8_t flags) {

    struct request *req = tmalloc(sizeof(*req));
    if (!req)
        goto err;

    req->reqtype = SINGLE_REQUEST;
    req->cmd = tmalloc(sizeof(struct command));
    if (!req->cmd)
        goto errnomem1;

    req->cmd->cmdtype = KEY_VAL_COMMAND;
    req->cmd->kv_cmd = tmalloc(sizeof(struct keyval_command));
    if (!req->cmd->kv_cmd)
        goto errnomem2;

    req->cmd->kv_cmd->hdr = tmalloc(sizeof(struct header));
    if (!req->cmd->kv_cmd->hdr)
        goto errnomem3;

    req->cmd->kv_cmd->hdr->size = HEADERLEN + (2 * sizeof(uint16_t))
        + strlen((const char *) key) + sizeof(uint32_t)
        + strlen((const char *) val) + sizeof(uint8_t);

    req->cmd->kv_cmd->hdr->flags = 0 | flags;

    if (flags & F_FROMNODEREQUEST) {
        char uuid[UUID_LEN];
        generate_uuid(uuid);
        strcpy(req->cmd->kv_cmd->hdr->transaction_id, uuid);
        req->cmd->kv_cmd->hdr->size += UUID_LEN - 1;
    }

    req->cmd->kv_cmd->hdr->opcode = opcode;

    req->cmd->kv_cmd->keysize = strlen((const char *) key);
    req->cmd->kv_cmd->key = (uint8_t *) tstrdup((const char *) key);

    req->cmd->kv_cmd->valsize = strlen((const char *) val);
    req->cmd->kv_cmd->val = (uint8_t *) tstrdup((const char *) val);

    req->cmd->kv_cmd->ttl = ttl;
    req->cmd->kv_cmd->is_prefix = flags & F_PREFIXREQUEST ? 1 : 0;

    return req;

errnomem3:

    tfree(req->cmd->kv_cmd);

errnomem2:

    tfree(req->cmd);

errnomem1:

    tfree(req);

err:

    return NULL;

}


struct request *make_keylist_request(const List *content,
                                     uint8_t opcode,
                                     const uint8_t *transaction_id,
                                     uint8_t flags) {

    struct request *req = tmalloc(sizeof(*req));
    if (!req)
        return NULL;

    req->reqtype = SINGLE_REQUEST;
    req->cmd = tmalloc(sizeof(struct command));
    if (!req->cmd) {
        tfree(req->cmd);
        return NULL;
    }

    req->cmd->kl_cmd = tmalloc(sizeof(struct key_list_command));
    if (!req->cmd->kl_cmd) {
        tfree(req->cmd);
        tfree(req);
        return NULL;
    }

    req->cmd->kl_cmd->hdr = tmalloc(sizeof(struct header));
    if (!req->cmd->kl_cmd->hdr) {
        tfree(req->cmd->kl_cmd);
        tfree(req->cmd);
        tfree(req);
        return NULL;
    }

    req->cmd->cmdtype = KEY_LIST_COMMAND;

    header_init(req->cmd->kl_cmd->hdr,
                opcode, HEADERLEN + sizeof(uint32_t),
                flags, (const char *) transaction_id);

    req->cmd->kl_cmd->len = content->len;
    req->cmd->kl_cmd->keys = tmalloc(content->len * sizeof(struct key));

    int i = 0;

    for (struct list_node *cur = content->head; cur; cur = cur->next) {
        struct key *key = tmalloc(sizeof(*key));
        key->key = (uint8_t *) tstrdup((const char *) cur->data);
        key->keysize = strlen((const char *) cur->data);
        req->cmd->kl_cmd->keys[i] = key;
        req->cmd->kl_cmd->hdr->size +=
            key->keysize + sizeof(uint16_t) + sizeof(uint8_t);
        i++;
    }

    return req;
}

/********************************************
 *         RESPONSE PACKING FUNCTIONS
 ********************************************/

void pack_response(struct buffer *buf, const struct response *res) {

    assert(buf && res);

    switch (res->restype) {
        case EMPTY_PAYLOAD:
            pack_header(res->e_pld->hdr, buf);
            pack_u8(buf, res->e_pld->code);
            break;
        case DATA_PAYLOAD:
            pack_header(res->d_pld->hdr, buf);
            // Mandatory fields
            pack_u32(buf, res->d_pld->datalen);
            pack_bytes(buf, res->d_pld->data);
            break;
        case VALUE_PAYLOAD:
            pack_header(res->v_pld->hdr, buf);
            // Mandatory fields
            pack_u32(buf, res->v_pld->val);
            break;
        case LIST_PAYLOAD:
            pack_header(res->l_pld->hdr, buf);
            pack_u16(buf, res->l_pld->len);

            for (int i = 0; i < res->l_pld->len; i++) {
                pack_u16(buf, res->l_pld->keys[i]->keysize);
                pack_bytes(buf, res->l_pld->keys[i]->key);
                pack_u8(buf, res->l_pld->keys[i]->is_prefix);
            }
            break;
        case KVLIST_PAYLOAD:

            pack_header(res->kvl_pld->hdr, buf);
            pack_u16(buf, res->kvl_pld->len);

            for (int i = 0; i < res->kvl_pld->len; i++) {
                pack_u16(buf, res->kvl_pld->pairs[i]->keysize);
                pack_u32(buf, res->kvl_pld->pairs[i]->valsize);
                pack_bytes(buf, res->kvl_pld->pairs[i]->key);
                pack_bytes(buf, res->kvl_pld->pairs[i]->val);
                pack_u8(buf, res->kvl_pld->pairs[i]->is_prefix);
            }
            break;
        default:
            fprintf(stderr, "Pack response: not implemented yet");
            break;
    }
}


struct response *unpack_response(struct buffer *buf) {

    assert(buf);

    struct response *res = tmalloc(sizeof(*res));
    if (!res)
        return NULL;

    struct header *hdr = tmalloc(sizeof(*hdr));
    if (!hdr)
        goto errnomem2;

    unpack_header(buf, hdr);

    // XXX not implemented all responses yet
    int8_t ctype = get_command_type(hdr->opcode);
    res->restype = get_content_type(hdr->opcode);

    switch (ctype) {

        case EMPTY_COMMAND:
            res->e_pld = tmalloc(sizeof(struct empty_payload));
            res->e_pld->hdr = hdr;
            res->e_pld->code = unpack_u8(buf);
            break;

        case KEY_COMMAND:
            res->d_pld = tmalloc(sizeof(struct data_payload));
            res->d_pld->hdr = hdr;
            res->d_pld->datalen = unpack_u32(buf);
            res->d_pld->data = unpack_bytes(buf, res->d_pld->datalen);
            break;

        case KEY_VAL_COMMAND:
            // TODO
            break;

        case KEY_VAL_LIST_COMMAND:
            res->kvl_pld = tmalloc(sizeof(struct kvlist_payload));
            res->kvl_pld->hdr = hdr;
            res->kvl_pld->len = unpack_u16(buf);
            res->kvl_pld->pairs =
                tmalloc(res->kvl_pld->len * sizeof(struct keyval));

            if (!res->kvl_pld->pairs)
                goto errnomem1;

            for (int i = 0; i < res->kvl_pld->len; i++) {
                struct keyval *kv = tmalloc(sizeof(*kv));
                kv->keysize = unpack_u16(buf);
                kv->valsize = unpack_u32(buf);
                kv->key = unpack_bytes(buf, kv->keysize);
                kv->val = unpack_bytes(buf, kv->valsize);
                kv->is_prefix = unpack_u8(buf);
                res->kvl_pld->pairs[i] = kv;
            }

            break;
    }

    return res;

errnomem1:

    tfree(hdr);

errnomem2:

    tfree(res);
    return NULL;
}


void free_response(struct response *res) {

    if (!res)
        return;

    switch (res->restype) {
        case EMPTY_PAYLOAD:
            tfree(res->e_pld->hdr);
            tfree(res->e_pld);
            break;
        case DATA_PAYLOAD:
            tfree(res->d_pld->hdr);
            tfree(res->d_pld->data);
            tfree(res->d_pld);
            break;
        case VALUE_PAYLOAD:
            tfree(res->v_pld->hdr);
            tfree(res->v_pld);
            break;
        case LIST_PAYLOAD:
            tfree(res->l_pld->hdr);
            for (int i = 0; i < res->l_pld->len; i++) {
                tfree(res->l_pld->keys[i]->key);
                tfree(res->l_pld->keys[i]);
            }
            tfree(res->l_pld->keys);
            tfree(res->l_pld);
            break;
        case KVLIST_PAYLOAD:
            tfree(res->kvl_pld->hdr);
            for (int i = 0; i < res->kvl_pld->len; i++) {
                tfree(res->kvl_pld->pairs[i]->key);
                tfree(res->kvl_pld->pairs[i]->val);
                tfree(res->kvl_pld->pairs[i]);
            }
            tfree(res->kvl_pld->pairs);
            tfree(res->kvl_pld);
            break;
        default:
            fprintf(stderr, "Free response: not implemented yet");
            break;
    }

    tfree(res);
}

/********************************************
 *             RESPONSE HELPERS
 ********************************************/

struct response *make_ack_response(uint8_t code,
                                   const uint8_t *transaction_id,
                                   uint8_t flags) {

    struct response *res = tmalloc(sizeof(*res));
    if (!res)
        goto errnomem3;

    res->e_pld = tmalloc(sizeof(struct empty_payload));
    if (!res->e_pld)
        goto errnomem2;

    res->e_pld->hdr = tmalloc(sizeof(struct header));
    if (!res->e_pld->hdr)
        goto errnomem1;

    ack_response_init(res, code, flags, (const char *) transaction_id);

    return res;

errnomem1:

    tfree(res->e_pld);

errnomem2:

    tfree(res);

errnomem3:

    return NULL;
}


struct response *make_data_response(const uint8_t *data,
                                    const uint8_t *transaction_id,
                                    uint8_t flags) {

    struct response *res = tmalloc(sizeof(*res));
    if (!res)
        goto errnomem3;

    res->d_pld = tmalloc(sizeof(struct data_payload));
    if (!res->d_pld)
        goto errnomem2;

    res->d_pld->hdr = tmalloc(sizeof(struct header));
    if (!res->d_pld->hdr)
        goto errnomem1;

    data_response_init(res, data, flags, (const char *) transaction_id);

    return res;

errnomem1:

    tfree(res->d_pld);

errnomem2:

    tfree(res);

errnomem3:

    return NULL;
}


struct response *make_valuecontent_response(uint32_t value,
                                            const uint8_t *transaction_id,
                                            uint8_t flags) {

    struct response *res = tmalloc(sizeof(*res));
    if (!res)
        goto errnomem3;

    res->v_pld = tmalloc(sizeof(struct value_payload));
    if (!res->v_pld)
        goto errnomem2;

    res->v_pld->hdr = tmalloc(sizeof(struct header));
    if (!res->v_pld->hdr)
        goto errnomem1;

    value_response_init(res, value, flags, (const char *) transaction_id);

    return res;

errnomem1:

    tfree(res->v_pld);

errnomem2:

    tfree(res);

errnomem3:

    return NULL;
}


struct response *make_list_response(const List *content,
                                    const uint8_t *transaction_id,
                                    uint8_t flags) {

    struct response *res = tmalloc(sizeof(*res));
    if (!res)
        return NULL;

    res->restype = LIST_PAYLOAD;
    res->l_pld = tmalloc(sizeof(struct list_payload));
    if (!res->l_pld) {
        tfree(res);
        return NULL;
    }

    res->l_pld->hdr = tmalloc(sizeof(struct header));
    if (!res->l_pld->hdr) {
        tfree(res->l_pld);
        tfree(res);
        return NULL;
    }

    header_init(res->l_pld->hdr, ACK, HEADERLEN + sizeof(uint16_t),
                flags, (const char *) transaction_id);

    res->l_pld->len = content->len;
    res->l_pld->keys = tcalloc(content->len, sizeof(struct key));

    int i = 0;

    for (struct list_node *cur = content->head; cur; cur = cur->next) {
        struct key *key = tmalloc(sizeof(*key));
        key->key = (uint8_t *) tstrdup((const char *) cur->data);
        key->keysize = strlen((const char *) cur->data);
        res->l_pld->keys[i] = key;
        res->l_pld->hdr->size +=
            key->keysize + sizeof(uint16_t) + sizeof(uint8_t);
        i++;
    }

    return res;
}


struct response *make_kvlist_response(const List *content,
                                      const uint8_t *transaction_id,
                                      uint8_t flags) {

    struct response *res = tmalloc(sizeof(*res));
    if (!res)
        return NULL;

    res->restype = KEY_VAL_LIST_COMMAND;
    res->kvl_pld = tmalloc(sizeof(struct kvlist_payload));
    if (!res->kvl_pld) {
        tfree(res);
        return NULL;
    }

    res->kvl_pld->hdr = tmalloc(sizeof(struct header));
    if (!res->kvl_pld->hdr) {
        tfree(res->kvl_pld);
        tfree(res);
        return NULL;
    }

    header_init(res->kvl_pld->hdr, CLUSTER_MEMBERS,
                HEADERLEN + sizeof(uint16_t), flags,
                (const char *) transaction_id);

    res->kvl_pld->len = content->len;
    res->kvl_pld->pairs = tmalloc(content->len * sizeof(struct keyval));

    int i = 0;

    for (struct list_node *cur = content->head; cur; cur = cur->next) {
        struct keyval *nodekv = cur->data;
        struct keyval *kv = tmalloc(sizeof(*kv));
        kv->key = (uint8_t *) tstrdup((const char *) nodekv->key);
        kv->keysize = nodekv->keysize;
        kv->val = (uint8_t *) tstrdup((const char *) nodekv->val);
        kv->valsize = nodekv->valsize;
        kv->is_prefix = 0;
        res->kvl_pld->pairs[i] = kv;
        res->kvl_pld->hdr->size += kv->keysize + kv->valsize +
            sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint8_t);
        i++;
    }

    return res;
}


void ack_response_init(struct response *res, uint8_t code,
                       int flags, const char *transaction_id) {

    res->restype = EMPTY_PAYLOAD;

    header_init(res->e_pld->hdr, ACK,
                HEADERLEN + sizeof(uint8_t), flags, transaction_id);

    res->e_pld->code = code;
}


void data_response_init(struct response *res, const uint8_t *data,
                        uint8_t flags, const char *transaction_id) {

    res->restype = DATA_PAYLOAD;

    uint32_t len = HEADERLEN + sizeof(uint32_t) + strlen((char *) data);
    header_init(res->d_pld->hdr, GET, len, flags, transaction_id);

    res->d_pld->datalen = strlen((char *) data);
    res->d_pld->data = (uint8_t *) tstrdup((const char *) data);
}


void value_response_init(struct response *res, uint32_t value,
                         uint8_t flags, const char *transaction_id) {

    res->restype = VALUE_PAYLOAD;

    header_init(res->v_pld->hdr, ACK,
                HEADERLEN + sizeof(uint32_t), flags, transaction_id);

    res->v_pld->val = value;
}
