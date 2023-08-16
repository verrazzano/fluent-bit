//
// Created by Aditya Bharadwaj on 07/07/23.
//

#include <sys/stat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_file.h>

#include <monkey/mk_core/mk_list.h>
#include <monkey/mk_core/mk_string.h>
#include <fluent-bit/flb_utils.h>

#include "oci_logan.h"
#include "oci_logan_conf.h"

static int build_region_table(struct flb_oci_logan *ctx) {
    ctx->region_table = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 100, 0);
    int len = sizeof(short_names) - 1;
    for(int i = 0; i < len; i++) {
        flb_hash_table_add(ctx->region_table,
                           short_names[i],
                           sizeof(short_names[i]) - 1,
                           long_names[i],
                           sizeof(long_names[i]) - 1);
    }

}
static int build_federation_client_headers(struct flb_oci_logan *ctx,
                                           struct flb_http_client *c,
                                           flb_sds_t json,
                                           flb_sds_t uri)
{
    int ret = -1;
    flb_sds_t tmp_sds = NULL;
    flb_sds_t signing_str = NULL;
    flb_sds_t rfc1123date = NULL;
    flb_sds_t encoded_uri = NULL;
    flb_sds_t signature = NULL;
    flb_sds_t auth_header_str = NULL;

    flb_sds_t tmp_ref = NULL;

    size_t tmp_len = 0;

    unsigned char sha256_buf[32] = { 0 };

    tmp_sds = flb_sds_create_size(512);
    if (!tmp_sds) {
        flb_errno();
        goto error_label;
    }

    signing_str = flb_sds_create_size(1024);
    if (!signing_str) {
        flb_errno();
        goto error_label;
    }

    // Add (requeset-target) to signing string
    encoded_uri = flb_uri_encode(uri, flb_sds_len(uri));
    if (!encoded_uri) {
        flb_errno();
        goto error_label;
    }
    signing_str = flb_sds_cat(signing_str, FLB_OCI_HEADER_REQUEST_TARGET,
                              sizeof(FLB_OCI_HEADER_REQUEST_TARGET) - 1);
    signing_str = flb_sds_cat(signing_str, ": post ", sizeof(": post ") - 1);
    signing_str = flb_sds_cat(signing_str, encoded_uri,
                              flb_sds_len(encoded_uri));

    // Add Date header
    rfc1123date = get_date();
    if (!rfc1123date) {
        flb_plg_error(ctx->ins, "cannot compose temporary date header");
        goto error_label;
    }
    signing_str = add_header_and_signing(c, signing_str, FLB_OCI_HEADER_DATE,
                                         sizeof(FLB_OCI_HEADER_DATE) - 1, rfc1123date,
                                         flb_sds_len(rfc1123date));
    if (!signing_str) {
        flb_plg_error(ctx->ins, "cannot compose signing string");
        goto error_label;
    }

    // Add x-content-sha256 Header
    ret = flb_hash_simple(FLB_HASH_SHA256,
                          (unsigned char*) json,
                          flb_sds_len(json),
                          sha256_buf, sizeof(sha256_buf));

    if (ret != FLB_CRYPTO_SUCCESS) {
        flb_plg_error(ctx->ins, "error forming hash buffer for x-content-sha256 Header");
        goto error_label;
    }

    flb_base64_encode((unsigned char*) tmp_sds, flb_sds_len(tmp_sds) - 1,
                      &tmp_len, sha256_buf, sizeof(sha256_buf));

    tmp_sds[tmp_len] = '\0';
    flb_sds_len_set(tmp_sds, tmp_len);

    signing_str = add_header_and_signing(c, signing_str,
                                         FLB_OCI_HEADER_X_CONTENT_SHA256,
                                         sizeof(FLB_OCI_HEADER_X_CONTENT_SHA256) - 1, tmp_sds,
                                         flb_sds_len(tmp_sds));
    if (!signing_str) {
        flb_plg_error(ctx->ins, "cannot compose signing string");
        goto error_label;
    }

    // Add content-Type
    signing_str = add_header_and_signing(c, signing_str,
                                         FLB_OCI_HEADER_CONTENT_TYPE, sizeof(FLB_OCI_HEADER_CONTENT_TYPE) - 1,
                                         FLB_OCI_HEADER_CONTENT_TYPE_FED_VAL,
                                         sizeof(FLB_OCI_HEADER_CONTENT_TYPE_FED_VAL) - 1);
    if (!signing_str) {
        flb_plg_error(ctx->ins, "cannot compose signing string");
        goto error_label;
    }

    // Add content-Length
    tmp_len = snprintf(tmp_sds, flb_sds_alloc(tmp_sds) - 1, "%i",
                       (int) flb_sds_len(json));
    flb_sds_len_set(tmp_sds, tmp_len);
    signing_str = add_header_and_signing(c, signing_str,
                                         FLB_OCI_HEADER_CONTENT_LENGTH, sizeof(FLB_OCI_HEADER_CONTENT_LENGTH) - 1,
                                         tmp_sds, flb_sds_len(tmp_sds));
    if (!signing_str) {
        flb_plg_error(ctx->ins, "cannot compose signing string");
        goto error_label;
    }

    // Add Authorization header
    signature = create_base64_sha256_signature(ctx->fed_client->leaf_cert_ret->private_key_pem,
                                               signing_str);
    if (!signature) {
        flb_plg_error(ctx->ins, "cannot compose signing signature");
        goto error_label;
    }

    auth_header_str = create_authorization_header_content(signature, ctx->fed_client->key_id);
    if (!auth_header_str) {
        flb_plg_error(ctx->ins, "cannot compose authorization header");
        goto error_label;
    }

    flb_http_add_header(c, FLB_OCI_HEADER_AUTH, sizeof(FLB_OCI_HEADER_AUTH) - 1,
                        auth_header_str, flb_sds_len(auth_header_str));

    // User-Agent
    flb_http_add_header(c, FLB_OCI_HEADER_USER_AGENT,
                        sizeof(FLB_OCI_HEADER_USER_AGENT) - 1,
                        FLB_OCI_HEADER_USER_AGENT_VAL,
                        sizeof(FLB_OCI_HEADER_USER_AGENT_VAL) - 1);

    // Accept
    flb_http_add_header(c, "Accept", 6, "*/*", 3);

    ret = 0;

    error_label:
    if (tmp_sds) {
        flb_sds_destroy(tmp_sds);
    }
    if (signing_str) {
        flb_sds_destroy(signing_str);
    }
    if (rfc1123date) {
        flb_sds_destroy(rfc1123date);
    }
    if (encoded_uri) {
        flb_sds_destroy(encoded_uri);
    }
    if (signature) {
        flb_sds_destroy(signature);
    }
    if (auth_header_str) {
        flb_sds_destroy(auth_header_str);
    }
    return ret;

}

int refresh_security_token(struct flb_oci_logan *ctx,
                           struct flb_config *config)
{
    flb_sds_t region;
    flb_sds_t host;
    char* err;
    struct flb_upstream *upstream;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    int ret = -1;
    time_t now;
    size_t b_sent;
    char *json = "";
    if (ctx->fed_client && ctx->fed_client->expire) {
        now = time(NULL);
        if (ctx->fed_client->expire > now) {
            return 0;
        }
    }
    if (!ctx->fed_client) {
        ctx->fed_client = flb_calloc(1, sizeof(struct federation_client));
    }
    if (!ctx->fed_client->leaf_cert_ret) {
        ctx->fed_client->leaf_cert_ret = flb_calloc(1, sizeof(struct cert_retriever));
    }
    if (!ctx->fed_client->intermediate_cert_ret) {
        ctx->fed_client->intermediate_cert_ret = flb_calloc(1, sizeof(struct cert_retriever));
    }

    ctx->fed_client->leaf_cert_ret->cert_pem = refresh_cert(ctx->cert_u,
                                                            LEAF_CERTIFICATE_URL,
                                                            ctx->ins);
    ctx->fed_client->leaf_cert_ret->private_key_pem = refresh_cert(ctx->cert_u,
                                                                   LEAF_CERTIFICATE_PRIVATE_KEY_URL,
                                                                   ctx->ins);
    ctx->fed_client->leaf_cert_ret->cert = get_cert_from_string(ctx->fed_client->leaf_cert_ret->cert_pem);

    ctx->fed_client->intermediate_cert_ret->cert_pem = refresh_cert(ctx->cert_u,
                                                                    INTERMEDIATE_CERTIFICATE_URL,
                                                                    ctx->ins);

    region = get_region(ctx->cert_u, GET_REGION_URL, ctx->region_table);
    flb_plg_info(ctx->ins, "region = %s", region);
    ctx->fed_client->region = region;
    host = flb_sds_create_size(512);
    flb_sds_snprintf(&host, flb_sds_alloc(host), "auth.%s.oci.oraclecloud.com", region);
    upstream = flb_upstream_create(config, host,  443,
                                   FLB_IO_TLS, ctx->ins->tls);
    if (!upstream) {
        return -1;
    }

    ctx->fed_u = upstream;
    ctx->fed_client->tenancy_id = get_tenancy_id_from_certificate(ctx->fed_client->leaf_cert_ret->cert);
    session_key_supplier(&ctx->fed_client->private_key,
                         &ctx->fed_client->public_key);

    ctx->fed_client->key_id = flb_sds_create_size(512);
    flb_sds_snprintf(&ctx->fed_client->key_id, flb_sds_alloc(ctx->fed_client->key_id),
                     "%s/fed-x509/%s", ctx->fed_client->tenancy_id, fingerprint(ctx->fed_client->leaf_cert_ret->cert));
    flb_plg_info(ctx->ins, "fed client key_id = %s", ctx->fed_client->key_id);

    // TODO: build headers
    u_conn = flb_upstream_conn_get(ctx->fed_u);
    if (!u_conn) {
        return -1;
    }

    sprintf(json,OCI_FEDERATION_REQUEST_PAYLOAD,
            sanitize_certificate_string(ctx->fed_client->leaf_cert_ret->cert_pem),
            sanitize_certificate_string(ctx->fed_client->public_key),
            sanitize_certificate_string(ctx->fed_client->intermediate_cert_ret->cert_pem));
    flb_plg_info(ctx->ins, "fed client payload = %s", json);

    c = flb_http_client(u_conn, FLB_HTTP_POST, "v1/x509",
                        json, strlen(json),
                        NULL, 0, NULL, 0);
    c->allow_dup_headers = FLB_FALSE;

    build_federation_client_headers(ctx, c, json, "v1/x509");


    for (int i = 0; i < 5; i++) {
        ret = flb_http_do(c, &b_sent);
        if (ret != 0) {
            continue;
        }
        if (c->resp.status != 200) {
            continue;
        }
        ctx->fed_client->security_token = parse_token(c->resp.payload,
                                                      c->resp.payload_size);
        break;

    }
    err = get_token_exp(ctx->fed_client->security_token, &ctx->fed_client->expire);
    if (err) {
        flb_plg_error(ctx->ins, "token error = %s",err);
        flb_upstream_conn_release(u_conn);
        flb_http_client_destroy(c);
        return -1;
    }
    flb_upstream_conn_release(u_conn);
    flb_http_client_destroy(c);
    return 0;

}

static int create_pk_context(flb_sds_t filepath, const char *key_passphrase,
                             struct flb_oci_logan *ctx)
{
    int ret;
    struct stat st;
    struct file_info finfo;
    FILE *fp;
    flb_sds_t kbuffer;


    ret = stat(filepath, &st);
    if (ret == -1) {
        flb_errno();
        flb_plg_error(ctx->ins, "cannot open key file %s", filepath);
        return -1;
    }

    if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) {
        flb_plg_error(ctx->ins, "key file is not a valid file: %s", filepath);
        return -1;
    }

    /* Read file content */
    if (mk_file_get_info(filepath, &finfo, MK_FILE_READ) != 0) {
        flb_plg_error(ctx->ins, "error to read key file: %s", filepath);
        return -1;
    }

    if (!(fp = fopen(filepath, "rb"))) {
        flb_plg_error(ctx->ins, "error to open key file: %s", filepath);
        return -1;
    }

    kbuffer = flb_sds_create_size(finfo.size + 1);
    if (!kbuffer) {
        flb_errno();
        fclose(fp);
        return -1;
    }

    ret = fread(kbuffer, finfo.size, 1, fp);
    if (ret < 1) {
        flb_sds_destroy(kbuffer);
        fclose(fp);
        flb_plg_error(ctx->ins, "fail to read key file: %s", filepath);
        return -1;
    }
    fclose(fp);

    /* In mbedtls, for PEM, the buffer must contains a null-terminated string */
    kbuffer[finfo.size] = '\0';
    flb_sds_len_set(kbuffer, finfo.size + 1);

    ctx->private_key = kbuffer;

    return 0;
}

static int load_oci_credentials(struct flb_oci_logan *ctx)
{
    flb_sds_t content;
    int found_profile = 0, res = 0;
    char *line, *profile;
    int eq_pos = 0;
    char* key;
    char* val;

    content = flb_file_read(ctx->config_file_location);
    if (content == NULL || flb_sds_len(content) == 0)
    {
        return -1;
    }
    flb_plg_info(ctx->ins, "content = %s", content);
    line = strtok(content, "\n");
    while(line != NULL) {
        // process line
        flb_plg_info(ctx->ins, "line = %s", line);
        if(!found_profile && line[0] == '[') {
            profile = mk_string_copy_substr(line, 1, strlen(line) - 1);
            if(!strcmp(profile, ctx->profile_name)) {
                flb_plg_info(ctx->ins, "found profile");
                found_profile = 1;
                goto iterate;
            }
        }
        if(found_profile) {
            if(line[0] == '[') {
                break;
            }
            eq_pos = mk_string_char_search(line, '=', strlen(line));
            flb_plg_info(ctx->ins, "eq_pos %d", eq_pos);
            key = mk_string_copy_substr(line, 0, eq_pos);
            flb_plg_info(ctx->ins, "key = %s", key);
            val = line + eq_pos + 1;
            if (!key || !val) {
                res = -1;
                break;
            }
            if (strcmp(key, FLB_OCI_PARAM_USER) == 0) {
                ctx->user = flb_sds_create(val);
                flb_plg_info(ctx->ins, "val = %s", val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_TENANCY) == 0) {
                ctx->tenancy = flb_sds_create(val);
                // flb_plg_info(ctx->ins, "val = %s", val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_KEY_FILE) == 0) {
                ctx->key_file = flb_sds_create(val);
                // flb_plg_info(ctx->ins, "val = %s", val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_KEY_FINGERPRINT) == 0) {
                ctx->key_fingerprint = flb_sds_create(val);
                // flb_plg_info(ctx->ins, "val = %s", val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_REGION) == 0) {
                ctx->region = flb_sds_create(val);
            }
            else {
                goto iterate;
            }
        }
        iterate:
        line = strtok(NULL, "\n");
    }
    if (!found_profile) {
        flb_errno();
        res = -1;
    }

    flb_sds_destroy(content);
    return res;
}

static int global_metadata_fields_create(struct flb_oci_logan *ctx)
{
    int i = 0;
    struct mk_list *head;
    struct flb_slist_entry *kname;
    struct flb_slist_entry *val;
    struct flb_config_map_val *mv;
    struct metadata_obj *f;

    if (!ctx->oci_la_global_metadata) {
        return 0;
    }

    flb_config_map_foreach(head, mv, ctx->oci_la_global_metadata) {
        kname = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        f = flb_malloc(sizeof(struct metadata_obj));
        if (!f) {
            flb_errno();
            return -1;
        }

        f->key = flb_sds_create(kname->str);
        if (!f->key) {
            flb_free(f);
            return -1;
        }
        f->val = flb_sds_create(val->str);
        if (!f->val) {
            flb_free(f);
            return -1;
        }


        mk_list_add(&f->_head, &ctx->global_metadata_fields);
    }

    return 0;
}

static int log_event_metadata_create(struct flb_oci_logan *ctx)
{
    int i = 0;
    struct mk_list *head;
    struct flb_slist_entry *kname;
    struct flb_slist_entry *val;
    struct flb_config_map_val *mv;
    struct metadata_obj *f;

    if (!ctx->oci_la_metadata) {
        return 0;
    }

    flb_config_map_foreach(head, mv, ctx->oci_la_metadata) {
        kname = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        f = flb_malloc(sizeof(struct metadata_obj));
        if (!f) {
            flb_errno();
            return -1;
        }

        f->key = flb_sds_create(kname->str);
        if (!f->key) {
            flb_free(f);
            return -1;
        }
        f->val = flb_sds_create(val->str);
        if (!f->val) {
            flb_free(f);
            return -1;
        }


        mk_list_add(&f->_head, &ctx->log_event_metadata_fields);
    }

    return 0;
}

struct flb_oci_logan *flb_oci_logan_conf_create(struct flb_output_instance *ins,
                                                struct flb_config *config) {
    struct flb_oci_logan *ctx;
    struct flb_upstream *upstream;
    flb_sds_t host = NULL;
    int io_flags = 0, default_port;
    const char *tmp;
    int ret = 0;
    char *protocol = NULL;
    char *p_host = NULL;
    char *p_port = NULL;
    char *p_uri = NULL;

    ctx = flb_calloc(1, sizeof(struct flb_oci_logan));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    ctx->ins = ins;

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "configuration error");
        flb_oci_logan_conf_destroy(ctx);
        return NULL;
    }

    build_region_table(ctx);

    if (strcmp(ctx->auth_type, INSTANCE_PRINCIPAL) == 0) {
        ctx->cert_u = flb_upstream_create(config, METADATA_HOST_BASE, 80, FLB_IO_TCP, NULL);
        refresh_security_token(ctx, config);
        ctx->region = ctx->fed_client->region;
        ctx->private_key = ctx->fed_client->private_key;
    }

    // TODO: fetch security token


    if (ctx->oci_la_global_metadata != NULL) {
        ret = global_metadata_fields_create(ctx);
        if (ret != 0) {
            flb_errno();
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
    }

    if (ctx->oci_la_metadata != NULL) {
        ret = log_event_metadata_create(ctx);
        if (ret != 0) {
            flb_errno();
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
    }

    if (strcasecmp(ctx->auth_type, USER_PRINCIPAL) == 0) {
        if (!ctx->config_file_location) {
            flb_errno();
            flb_plg_error(ctx->ins, "config file location is required");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }

        ret = load_oci_credentials(ctx);
        if (ret != 0) {
            flb_errno();
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
    }

    if (ins->host.name) {
        host = ins->host.name;
    }
    else {
        if (!ctx->region) {
            flb_errno();
            flb_plg_error(ctx->ins, "Region is required");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
        host = flb_sds_create_size(512);
        flb_sds_snprintf(&host, flb_sds_alloc(host), "loganalytics.%s.oci.oraclecloud.com", ctx->region);
    }

    if (!ctx->uri) {
        if (!ctx->namespace) {
            flb_errno();
            flb_plg_error(ctx->ins, "Namespace is required");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
        ctx->uri = flb_sds_create_size(512);
        flb_sds_snprintf(&ctx->uri, flb_sds_alloc(ctx->uri),
                       "/20200601/namespaces/%s/actions/uploadLogEventsFile",
                       ctx->namespace);
    }



    if (strcasecmp(ctx->auth_type, USER_PRINCIPAL) == 0) {
        if (create_pk_context(ctx->key_file, NULL, ctx) < 0) {
            flb_plg_error(ctx->ins, "failed to create pk context");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
    }



    ctx->key_id = flb_sds_create_size(512);
    if (!strcasecmp(ctx->auth_type, USER_PRINCIPAL)) {
        flb_sds_snprintf(&ctx->key_id, flb_sds_alloc(ctx->key_id),
                         "%s/%s/%s", ctx->tenancy, ctx->user, ctx->key_fingerprint);
    }
    else if (!strcasecmp(ctx->auth_type, INSTANCE_PRINCIPAL)) {
        flb_sds_snprintf(&ctx->key_id, flb_sds_alloc(ctx->key_id),
                         "ST$%s", ctx->fed_client->security_token);
    }

    /* Check if SSL/TLS is enabled */
    io_flags = FLB_IO_TCP;
    default_port = 80;

#ifdef FLB_HAVE_TLS
    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
        default_port = 443;
    }
#endif

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    flb_output_net_default(host, default_port, ins);

    if (ctx->proxy) {
        ret = flb_utils_url_split(tmp, &protocol, &p_host, &p_port, &p_uri);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "could not parse proxy parameter: '%s'", tmp);
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }

        ctx->proxy_host = p_host;
        ctx->proxy_port = atoi(p_port);
        flb_free(protocol);
        flb_free(p_port);
        flb_free(p_uri);
        flb_free(p_host);
    }

    if (ctx->proxy) {
        upstream = flb_upstream_create(config, ctx->proxy_host, ctx->proxy_port,
                                       io_flags, ins->tls);
    }
    else {
        /* Prepare an upstream handler */
        upstream = flb_upstream_create(config, ins->host.name, ins->host.port,
                                       io_flags, ins->tls);
    }

    if (!upstream) {
        flb_plg_error(ctx->ins, "cannot create Upstream context");
        flb_oci_logan_conf_destroy(ctx);
        return NULL;
    }
    ctx->u = upstream;

    /* Set instance flags into upstream */
    flb_output_upstream_set(ctx->u, ins);

    return ctx;
}

int flb_oci_logan_conf_destroy(struct flb_oci_logan *ctx) {
    if(ctx == NULL) {
        return 0;
    }

    if(ctx->oci_la_entity_id) {
        flb_sds_destroy(ctx->oci_la_entity_id);
    }
    if(ctx->oci_la_log_set_id) {
        flb_sds_destroy(ctx->oci_la_log_set_id);
    }
    if(ctx->namespace) {
        flb_sds_destroy(ctx->namespace);
    }
    if(ctx->oci_la_log_path) {
        flb_sds_destroy(ctx->oci_la_log_path);
    }
    if(ctx->oci_la_entity_type) {
        flb_sds_destroy(ctx->oci_la_entity_type);
    }
    if(ctx->oci_la_log_group_id) {
        flb_sds_destroy(ctx->oci_la_log_group_id);
    }
    if(ctx->oci_la_log_source_name) {
        flb_sds_destroy(ctx->oci_la_log_source_name);
    }
    if(ctx->config_file_location) {
        flb_sds_destroy(ctx->config_file_location);
    }
    if (ctx->private_key) {
        flb_sds_destroy(ctx->private_key);
    }
    if (ctx->uri) {
        flb_sds_destroy(ctx->uri);
    }
    if (ctx->key_id) {
        flb_sds_destroy(ctx->key_id);
    }
    if (ctx->key_file) {
        flb_sds_destroy(ctx->key_file);
    }
    if(ctx->user) {
        flb_sds_destroy(ctx->user);
    }
    if(ctx->key_fingerprint) {
        flb_sds_destroy(ctx->key_fingerprint);
    }
    if(ctx->tenancy) {
        flb_sds_destroy(ctx->tenancy);
    }
    if(ctx->region) {
        flb_sds_destroy(ctx->region);
    }

    flb_free(ctx);
    return 0;
}