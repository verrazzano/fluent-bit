//
// Created by Aditya Bharadwaj on 16/10/23.
//

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/oracle/flb_oracle_client.h>
#include "oci_logging.h"
#include "oci_logging_conf.h"

/*
 * Do a stack based DFS to flatten nested keys and form data string out of record map.
 * The data string will be a json formatted string, with nested values such as '{"key1":{"key2":val}}'
 * will turn into '{"key1.key2":val}'.
 */
static int format_data(msgpack_object *data, flb_sds_t *out_buf)
{
    int ret;
    struct mk_list stack, data_list;
    struct nested *cur;
    struct nested *new_obj;
    struct nested *child;
    struct data_kv *item;
    struct data_kv *itr;
    struct mk_list *head;
    struct mk_list *tmp;
    int i, pop, data_size;

    msgpack_sbuffer data_sbuf;
    msgpack_packer data_pck;

    mk_list_init(&stack);
    mk_list_init(&data_list);
    msgpack_sbuffer_init(&data_sbuf);
    msgpack_packer_init(&data_pck, &data_sbuf, msgpack_sbuffer_write);

    new_obj = flb_calloc(1, sizeof(struct nested));

    new_obj->obj = data;
    new_obj->cur_index = 0;
    new_obj->flattened_key = NULL;
    mk_list_add(&new_obj->_head, &stack);

    while (mk_list_is_empty(&stack) == -1) {
        cur = mk_list_entry_last(&stack, struct nested, _head);
        pop = FLB_TRUE;
        for (i = cur->cur_index; i < cur->obj->via.map.size; i++) {
            if(cur->obj->via.map.ptr[i].key.type != MSGPACK_OBJECT_STR) {
                continue;
            }
            if(cur->obj->via.map.ptr[i].val.type == MSGPACK_OBJECT_MAP) {
                child = flb_calloc(1, sizeof(struct nested));
                child->obj = &cur->obj->via.map.ptr[i].val;
                child->cur_index = 0;
                if (cur->flattened_key != NULL) {
                    flb_sds_snprintf(&child->flattened_key,
                                     sizeof(child->flattened_key),
                                     "%s.%s", cur->flattened_key,
                                     cur->obj->via.map.ptr[i].key.via.str.ptr);
                }
                else {
                    child->flattened_key = flb_sds_create_len(cur->obj->via.map.ptr[i].key.via.str.ptr,
                                                              cur->obj->via.map.ptr[i].key.via.str.size);
                }
                mk_list_add(&child->_head, &stack);
                cur->cur_index = i + 1;
                pop = FLB_FALSE;
                break;
            }
            else {
                item = flb_calloc(1, sizeof(struct data_kv));
                if(strcmp(cur->obj->via.map.ptr[i].key.via.str.ptr, "log") == 0 ||
                   strcmp(cur->obj->via.map.ptr[i].key.via.str.ptr, "msg") == 0 ||
                   strcmp(cur->obj->via.map.ptr[i].key.via.str.ptr, "message") == 0) {
                    item->key = flb_sds_create_len("msg", 3);
                }
                else if (cur->flattened_key != NULL) {
                    flb_sds_snprintf(&item->key,
                                     sizeof(item->key),
                                     "%s.%s", cur->flattened_key,
                                     cur->obj->via.map.ptr[i].key.via.str.ptr);
                }
                else {
                    item->key = flb_sds_create_len(cur->obj->via.map.ptr[i].key.via.str.ptr,
                                                   cur->obj->via.map.ptr[i].key.via.str.size);
                }
                item->val = &cur->obj->via.map.ptr[i].val;
                mk_list_add(&item->_head, &data_list);
            }
        }
        if (pop == FLB_TRUE) {
            mk_list_del(&cur->_head);
            flb_free(cur);
        }
    }

    data_size = mk_list_size(&data_list);
    msgpack_pack_map(&data_pck, data_size);
    while(mk_list_is_empty(&data_list) == -1) {
        itr = mk_list_entry_last(&data_list, struct data_kv, _head);
        msgpack_pack_str(&data_pck, flb_sds_len(item->key));
        msgpack_pack_str_body(&data_pck, itr->key, flb_sds_len(itr->key));
        msgpack_pack_object(&data_pck, *itr->val);
        mk_list_del(&itr->_head);
        flb_free(itr);
    }

    *out_buf = flb_msgpack_raw_to_json_sds(data_sbuf.data, data_sbuf.size);
    msgpack_sbuffer_destroy(&data_sbuf);

    return 0;
}
static int cb_oci_logging_init(struct flb_output_instance *ins,
                             struct flb_config *config,
                             void *data)
{
    struct flb_oci_logging *ctx;
    ctx = flb_oci_logging_conf_create(ins, config);
    if (!ctx) {
        flb_plg_error(ins, "cannot initialize plugin");
        return -1;
    }
    flb_plg_info(ins, "initialized logan plugin");
    flb_output_set_context(ins, ctx);
    flb_output_set_http_debug_callbacks(ins);

    return 0;
}

static int flush_to_endpoint(struct flb_oci_logging *ctx,
                             flb_sds_t payload)
{
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    int out_ret, http_ret;
    size_t b_sent;
    u_conn = flb_upstream_conn_get(ctx->u);
    if(!u_conn) {
        goto error_label;
    }
    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->uri, (void*) payload,
                        flb_sds_len(payload), ctx->ins->host.name, ctx->ins->host.port, ctx->proxy, 0);
    if (!c) {
        goto error_label;
    }
    flb_http_allow_duplicated_headers(c, FLB_FALSE);

    flb_plg_debug(ctx->ins, "built client");
    flb_http_buffer_size(c, FLB_HTTP_DATA_SIZE_MAX);
    if (build_headers(c, ctx->private_key, ctx->key_id,
                      payload,
                      ctx->ins->host.name,
                      ctx->ins->host.port,
                      ctx->uri, ctx->ins) < 0) {
        flb_plg_error(ctx->ins, "failed to build headers");
        goto error_label;
    }
    flb_plg_debug(ctx->ins, "built request");

    out_ret = FLB_OK;

    http_ret = flb_http_do(c, &b_sent);
    flb_plg_debug(ctx->ins, "placed request");

    if (http_ret == 0) {
        if (c->resp.status != 200) {
            flb_plg_debug(ctx->ins, "request header %s", c->header_buf);
            out_ret = FLB_RETRY;
            flb_plg_error(ctx->ins, "could not flush records to %s:%i (http_do=%i), retry=%s",
                          ctx->ins->host.name, ctx->ins->host.port,
                          http_ret, (out_ret == FLB_RETRY ? "true" : "false"));
        }
    }
    else {
        out_ret = FLB_RETRY;
        flb_plg_error(ctx->ins, "could not flush records to %s:%i (http_do=%i), retry=%s",
                      ctx->ins->host.name, ctx->ins->host.port,
                      http_ret, (out_ret == FLB_RETRY ? "true" : "false"));
        goto error_label;
    }

    error_label:
    /* Destroy HTTP client context */
    if (c) {
        flb_http_client_destroy(c);
    }

    /* Release the TCP connection */
    if (u_conn) {
        flb_upstream_conn_release(u_conn);
    }

    return out_ret;
}

static void cb_oci_logging_flush(struct flb_event_chunk *event_chunk,
                               struct flb_output_flush *out_flush,
                               struct flb_input_instance *ins, void *out_context,
                               struct flb_config *config)
{
    struct flb_oci_logging *ctx = out_context;
    flb_sds_t out_buf = NULL;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    msgpack_object map;
    int map_size;
    int num_records;
    msgpack_sbuffer mp_sbuf, tmp_sbuf;
    msgpack_packer mp_pck, tmp_pck;
    struct msgpack_object_kv tmp;
    int ret = 0, i, flush_ret = FLB_RETRY;
    flb_sds_t rec_data;

    num_records = flb_mp_count(event_chunk->data, event_chunk->size);
    ret = flb_log_event_decoder_init(&log_decoder, (char *) event_chunk->data, event_chunk->size);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);
        // res = FLB_ERROR;
        goto clean_up;
    }

    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&mp_pck, 2);
    msgpack_pack_str(&mp_pck, FLB_OCI_CLIENT_SPEC_VERSION_SIZE);
    msgpack_pack_str_body(&mp_pck, FLB_OCI_CLIENT_SPEC_VERSION, FLB_OCI_CLIENT_SPEC_VERSION_SIZE);

    msgpack_pack_str(&mp_pck, 3);
    msgpack_pack_str_body(&mp_pck, "1.0", 3);

    msgpack_pack_str(&mp_pck, FLB_OCI_LOG_ENTRY_BATCHES_SIZE);
    msgpack_pack_str_body(&mp_pck, FLB_OCI_LOG_ENTRY_BATCHES, FLB_OCI_LOG_ENTRY_BATCHES_SIZE);

    msgpack_pack_array(&mp_pck, num_records);
    msgpack_pack_map(&mp_pck, 5);

    while ((ret = flb_log_event_decoder_next(
        &log_decoder,
        &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        map = *log_event.body;
        map_size = map.via.map.size;
        msgpack_pack_map(&mp_pck, 5);

        msgpack_pack_str(&mp_pck, 6);
        msgpack_pack_str_body(&mp_pck, "source", 6);

        // TODO: pack source

        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "type", 4);

        // TODO: pack type

        msgpack_pack_str(&mp_pck, 7);
        msgpack_pack_str_body(&mp_pck, "subject", 7);

        // TODO: pack subject

        msgpack_pack_str(&mp_pck, FLB_DEFAULT_LOG_ENTRY_TIME_SIZE);
        msgpack_pack_str_body(&mp_pck, FLB_DEFAULT_LOG_ENTRY_TIME, FLB_DEFAULT_LOG_ENTRY_TIME_SIZE);

        // TODO: pack time

        msgpack_pack_str(&mp_pck, 7);
        msgpack_pack_str_body(&mp_pck, "entries", 7);

        msgpack_pack_array(&mp_pck, 3);

        msgpack_pack_str(&mp_pck, 2);
        msgpack_pack_str_body(&mp_pck, "id", 2);

        // TODO: pack id

        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "time", 4);

        // TODO: pack time

        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "data", 4);

        format_data(&map, &rec_data);
        msgpack_pack_str(&mp_pck, flb_sds_len(rec_data));
        msgpack_pack_str_body(&mp_pck, rec_data, flb_sds_len(rec_data));
    }

    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);
    flb_log_event_decoder_destroy(&log_decoder);

    // TODO: flush data
    ret = flush_to_endpoint(ctx, out_buf);

    if (ret == FLB_OK) {
        flb_plg_debug(ctx->ins, "success");
    }

clean_up:
    if (out_buf != NULL) {
        flb_sds_destroy(out_buf);
    }
    FLB_OUTPUT_RETURN(ret);
}

static int cb_oci_logging_exit(void *data, struct flb_config *config)
{
    struct flb_oci_logging *ctx = data;

    return flb_oci_logging_conf_destroy(ctx);
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {};
/* Plugin reference */
struct flb_output_plugin out_oracle_logging_plugin = {
    .name           = "oracle_logging",
    .description    = "Oracle Cloud Infrastructure Logging",
    .cb_init        = cb_oci_logging_init,
    .cb_pre_run     = NULL,
    .cb_flush       = cb_oci_logging_flush,
    .cb_exit        = cb_oci_logging_exit,

    /* Configuration */
    .config_map     = config_map,

    /* Events supported */
    .event_type   = FLB_OUTPUT_LOGS,


    /* Plugin flags */
    .flags          = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
    .workers = 1,
};
