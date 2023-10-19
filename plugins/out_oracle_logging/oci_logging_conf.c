//
// Created by Aditya Bharadwaj on 16/10/23.
//

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include "oci_logging_conf.h"
#include "oci_logging.h"

struct flb_oci_logging *flb_oci_logging_conf_create(struct flb_output_instance *ins,
                                                    struct flb_config *config)
{
    struct flb_oci_logging *ctx;
    struct flb_upstream *upstream;
    flb_sds_t host = NULL;
    int io_flags = 0, default_port;
    const char *tmp;
    int ret = 0;
    char *protocol = NULL;
    char *p_host = NULL;
    char *p_port = NULL;
    char *p_uri = NULL;

    ctx = flb_calloc(1, sizeof(struct flb_oci_logging));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    ctx->ins = ins;

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "configuration error");
        flb_oci_logging_conf_destroy(ctx);
        return NULL;
    }

    if (!ctx->config_file_location) {
        flb_errno();
        flb_plg_error(ctx->ins, "config file location is required");
        flb_oci_logging_conf_destroy(ctx);
        return NULL;
    }

    // move out to common location
    ret = load_oci_credentials(ctx);
    if(ret != 0) {
        flb_errno();
        flb_oci_logging_conf_destroy(ctx);
        return NULL;
    }

    if (ins->host.name) {
        host = ins->host.name;
    }
    else {
        if (!ctx->region) {
            flb_errno();
            flb_plg_error(ctx->ins, "Region is required");
            flb_oci_logging_conf_destroy(ctx);
            return NULL;
        }
        host = flb_sds_create_size(512);
        flb_sds_snprintf(&host, flb_sds_alloc(host), "ingestion.logging.%s.oci.oraclecloud.com", ctx->region);
    }

    if (!ctx->uri) {
        ctx->uri = flb_sds_create_size(1024);
        flb_sds_snprintf(&ctx->uri, flb_sds_alloc(ctx->uri),
                         "/20200831/logs/%s/actions/push",
                         ctx->log_group_id);
    }


    // move out to common location
    if (create_pk_context(ctx->key_file, NULL, ctx) < 0) {
        flb_plg_error(ctx->ins, "failed to create pk context");
        flb_oci_logging_conf_destroy(ctx);
        return NULL;
    }


    ctx->key_id = flb_sds_create_size(512);
    flb_sds_snprintf(&ctx->key_id, flb_sds_alloc(ctx->key_id),
                     "%s/%s/%s", ctx->tenancy, ctx->user, ctx->key_fingerprint);


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
    flb_sds_destroy(host);

    if (ctx->proxy) {
        ret = flb_utils_url_split(tmp, &protocol, &p_host, &p_port, &p_uri);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "could not parse proxy parameter: '%s'", tmp);
            flb_oci_logging_conf_destroy(ctx);
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
        flb_oci_logging_conf_destroy(ctx);
        return NULL;
    }
    ctx->u = upstream;

    /* Set instance flags into upstream */
    flb_output_upstream_set(ctx->u, ins);

    return ctx;

}

int flb_oci_logging_conf_destroy(struct flb_oci_logging *ctx)
{
    return 0;
}