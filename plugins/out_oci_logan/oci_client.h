//
// Created by Aditya Bharadwaj on 23/07/23.
//

#ifndef FLUENT_BIT_OUT_OCI_LOGAN_OCI_CLIENT_H
#define FLUENT_BIT_OUT_OCI_LOGAN_OCI_CLIENT_H

#endif //FLUENT_BIT_PLUGINS_OUT_OCI_LOGAN_OCI_CLIENT_H_

#include <fluent-bit/flb_sds.h>

struct request_signer {
    flb_sds_t user_id;
    flb_sds_t tenancy_id;
    flb_sds_t region;
    flb_sds_t private_key;
    flb_sds_t key_fingerprint;
    flb_sds_t key_id;
    flb_sds_t auth_type;
};

struct request_signer *build_instance_principal_signer();
struct request_signer *build_user_principal_signer();
struct request_signer *build_workload_identity_signer();