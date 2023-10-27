//
// Created by Aditya Bharadwaj on 23/10/23.
//

#ifndef FLUENT_BIT_INCLUDE_FLUENT_BIT_ORACLE_FLB_ORACLE_CLIENT_H_
#define FLUENT_BIT_INCLUDE_FLUENT_BIT_ORACLE_FLB_ORACLE_CLIENT_H_

/* Http Header */
#define FLB_OCI_HEADER_REQUEST_TARGET           "(request-target)"
#define FLB_OCI_HEADER_USER_AGENT                      "User-Agent"
#define FLB_OCI_HEADER_USER_AGENT_VAL                  "Fluent-Bit"
#define FLB_OCI_HEADER_CONTENT_TYPE                    "content-type"
#define FLB_OCI_HEADER_CONTENT_TYPE_VAL                "application/json"
#define FLB_OCI_HEADER_X_CONTENT_SHA256                "x-content-sha256"
#define FLB_OCI_HEADER_CONTENT_LENGTH                  "content-length"
#define FLB_OCI_HEADER_HOST                            "host"
#define FLB_OCI_HEADER_DATE                            "date"
#define FLB_OCI_HEADER_AUTH                            "Authorization"
#define FLB_OCI_PAYLOAD_TYPE                           "payloadType"

/* For OCI signing */
#define FLB_OCI_PARAM_TENANCY     "tenancy"
#define FLB_OCI_PARAM_USER        "user"
#define FLB_OCI_PARAM_KEY_FINGERPRINT     "fingerprint"
#define FLB_OCI_PARAM_KEY_FILE     "key_file"
#define FLB_OCI_PARAM_REGION  "region"
#define FLB_OCI_PARAM_KEY_FILE_PASSPHRASE "key_file_passphrase"

#define FLB_OCI_SIGN_SIGNATURE_VERSION   "Signature version=\"1\""
#define FLB_OCI_SIGN_KEYID   "keyId"
#define FLB_OCI_SIGN_ALGORITHM   "algorithm=\"rsa-sha256\""

#define FLB_OCI_SIGN_HEADERS     "headers=\"" \
    FLB_OCI_HEADER_REQUEST_TARGET " " \
    FLB_OCI_HEADER_HOST " " \
    FLB_OCI_HEADER_DATE " " \
    FLB_OCI_HEADER_X_CONTENT_SHA256 " " \
    FLB_OCI_HEADER_CONTENT_TYPE " " \
    FLB_OCI_HEADER_CONTENT_LENGTH "\""

#define FLB_OCI_SIGN_SIGNATURE   "signature"

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_output_plugin.h>

int create_pk_context(flb_sds_t filepath,
                      const char *key_passphrase,
                      struct flb_output_instance *ins,
                      flb_sds_t *p_key);

int load_oci_credentials(struct flb_output_instance *ins,
                         flb_sds_t config_file_location,
                         flb_sds_t profile_name,
                         flb_sds_t *user, flb_sds_t *tenancy,
                         flb_sds_t *key_file, flb_sds_t *key_fingerprint,
                         flb_sds_t *region);
flb_sds_t create_authorization_header_content(flb_sds_t key_id,
                                              flb_sds_t signature);
flb_sds_t create_base64_sha256_signature(flb_sds_t private_key,
                                         flb_sds_t signing_string,
                                         struct flb_output_instance *ins);
flb_sds_t get_date(void);
flb_sds_t add_header_and_signing(struct flb_http_client *c,
                                 flb_sds_t signing_str, const char *header, int headersize,
                                 const char *val, int val_size);
int build_headers(struct flb_http_client *c, flb_sds_t private_key,
                  flb_sds_t key_id, flb_sds_t json, flb_sds_t hostname,
                  int port, flb_sds_t uri, struct flb_output_instance *ins);

#endif //FLUENT_BIT_INCLUDE_FLUENT_BIT_ORACLE_FLB_ORACLE_CLIENT_H_
