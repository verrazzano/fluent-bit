//
// Created by Aditya Bharadwaj on 16/10/23.
//

#ifndef FLB_OUT_ORACLE_LOGGING_H
#define FLB_OUT_ORACLE_LOGGING_H

#define FLB_OCI_CLIENT_SPEC_VERSION "specversion"
#define FLB_OCI_CLIENT_SPEC_VERSION_SIZE sizeof(FLB_OCI_CLIENT_SPEC_VERSION) - 1

#define FLB_OCI_LOG_ENTRY_BATCHES "logEntryBatches"
#define FLB_OCI_LOG_ENTRY_BATCHES_SIZE sizeof(FLB_OCI_LOG_ENTRY_BATCHES) - 1

#define FLB_DEFAULT_LOG_ENTRY_TIME "defaultlogentrytime"
#define FLB_DEFAULT_LOG_ENTRY_TIME_SIZE sizeof(FLB_DEFAULT_LOG_ENTRY_TIME) - 1
#include <fluent-bit/flb_sds.h>

struct nested {
    msgpack_object *obj;
    flb_sds_t flattened_key;
    int cur_index;
    struct mk_list _head;
};

struct data_kv {
    flb_sds_t key;
    msgpack_object *val;
    struct mk_list _head;
};

struct flb_oci_logging {
    flb_sds_t log_group_id;
    flb_sds_t namespace;
    flb_sds_t config_file_location;
    flb_sds_t profile_name;
    flb_sds_t uri;

    struct flb_upstream *u;
    flb_sds_t proxy;
    char *proxy_host;
    int proxy_port;
    flb_sds_t user;
    flb_sds_t region;
    flb_sds_t tenancy;
    flb_sds_t key_fingerprint;
    flb_sds_t key_file;
    /* For OCI signing */
    flb_sds_t key_id; // tenancy/user/key_fingerprint
    flb_sds_t private_key;

    struct flb_output_instance *ins;
};

#endif
