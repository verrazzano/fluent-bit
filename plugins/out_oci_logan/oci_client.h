//
// Created by Aditya Bharadwaj on 23/07/23.
//

#ifndef FLUENT_BIT_OUT_OCI_LOGAN_OCI_CLIENT_H
#define FLUENT_BIT_OUT_OCI_LOGAN_OCI_CLIENT_H

#define FLB_OCI_TOKEN "token"
#define RSA_KEYLEN 2048

#endif //FLUENT_BIT_PLUGINS_OUT_OCI_LOGAN_OCI_CLIENT_H_

#include <fluent-bit/flb_sds.h>
#include <openssl/x509.h>
#include <fluent-bit/flb_upstream.h>

struct request_signer *build_instance_principal_signer();
struct request_signer *build_user_principal_signer();
struct request_signer *build_workload_identity_signer();