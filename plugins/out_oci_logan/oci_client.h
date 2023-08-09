//
// Created by Aditya Bharadwaj on 23/07/23.
//

#ifndef FLUENT_BIT_OUT_OCI_LOGAN_OCI_CLIENT_H
#define FLUENT_BIT_OUT_OCI_LOGAN_OCI_CLIENT_H

#endif //FLUENT_BIT_PLUGINS_OUT_OCI_LOGAN_OCI_CLIENT_H_

#include <fluent-bit/flb_sds.h>
#include <openssl/x509.h>

struct request_signer {
    flb_sds_t user_id;
    flb_sds_t tenancy_id;
    flb_sds_t region;
    flb_sds_t private_key;
    flb_sds_t key_fingerprint;
    flb_sds_t key_id;
};

struct federation_client {
    flb_sds_t host;
    int port;
    flb_sds_t tenancy_id;
    struct cert_retriever *leaf_cert_ret;
    struct cert_retriever *intermediate_cert_ret;
    // session key supplier
    flb_sds_t security_token;
    pthread_mutex_t lock;
};

struct cert_retriever {
    struct flb_upstream u;
    flb_sds_t cert_url;
    flb_sds_t priv_key_url;
    flb_sds_t cert_pem;
    X509 *cert;
    flb_sds_t private_key_pem;
};

struct request_signer *build_instance_principal_signer();
struct request_signer *build_user_principal_signer();
struct request_signer *build_workload_identity_signer();