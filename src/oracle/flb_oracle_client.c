//
// Created by Aditya Bharadwaj on 23/10/23.
//

#include <sys/stat.h>
#include <fluent-bit/oracle/flb_oracle_client.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_file.h>
#include <fluent-bit/flb_crypto.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_hash.h>

int create_pk_context(flb_sds_t filepath,
                      const char *key_passphrase,
                      struct flb_output_instance *ins,
                      flb_sds_t *p_key)
{
    int ret;
    struct stat st;
    struct file_info finfo;
    FILE *fp;
    flb_sds_t kbuffer;


    ret = stat(filepath, &st);
    if (ret == -1) {
        flb_errno();
        flb_plg_error(ins, "cannot open key file %s", filepath);
        return -1;
    }

    if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) {
        flb_plg_error(ins, "key file is not a valid file: %s", filepath);
        return -1;
    }

    /* Read file content */
    if (mk_file_get_info(filepath, &finfo, MK_FILE_READ) != 0) {
        flb_plg_error(ins, "error to read key file: %s", filepath);
        return -1;
    }

    if (!(fp = fopen(filepath, "rb"))) {
        flb_plg_error(ins, "error to open key file: %s", filepath);
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
        flb_plg_error(ins, "fail to read key file: %s", filepath);
        return -1;
    }
    fclose(fp);

    /* In mbedtls, for PEM, the buffer must contains a null-terminated string */
    kbuffer[finfo.size] = '\0';
    flb_sds_len_set(kbuffer, finfo.size + 1);

    *p_key = kbuffer;

    return 0;
}

int load_oci_credentials(struct flb_output_instance *ins,
                         flb_sds_t config_file_location,
                         flb_sds_t profile_name,
                         flb_sds_t *user, flb_sds_t *tenancy,
                         flb_sds_t *key_file, flb_sds_t *key_fingerprint,
                         flb_sds_t *region)
{
    flb_sds_t content;
    int found_profile = 0, res = 0;
    char *line, *profile = NULL;
    int eq_pos = 0;
    char* key = NULL;
    char* val;

    content = flb_file_read(config_file_location);
    if (content == NULL || flb_sds_len(content) == 0)
    {
        return -1;
    }
    flb_plg_debug(ins, "content = %s", content);
    line = strtok(content, "\n");
    while(line != NULL) {
        /* process line */
        flb_plg_debug(ins, "line = %s", line);
        if(!found_profile && line[0] == '[') {
            profile = mk_string_copy_substr(line, 1, strlen(line) - 1);
            if(!strcmp(profile, profile_name)) {
                flb_plg_info(ins, "found profile");
                found_profile = 1;
                goto iterate;
            }
            mk_mem_free(profile);
        }
        if(found_profile) {
            if(line[0] == '[') {
                break;
            }
            eq_pos = mk_string_char_search(line, '=', strlen(line));
            flb_plg_debug(ins, "eq_pos %d", eq_pos);
            key = mk_string_copy_substr(line, 0, eq_pos);
            flb_plg_debug(ins, "key = %s", key);
            val = line + eq_pos + 1;
            if (!key || !val) {
                res = -1;
                break;
            }
            if (strcmp(key, FLB_OCI_PARAM_USER) == 0) {
                *user = flb_sds_create(val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_TENANCY) == 0) {
                *tenancy = flb_sds_create(val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_KEY_FILE) == 0) {
                *key_file = flb_sds_create(val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_KEY_FINGERPRINT) == 0) {
                *key_fingerprint = flb_sds_create(val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_REGION) == 0) {
                *region = flb_sds_create(val);
            }
            else {
                goto iterate;
            }
        }
        iterate:
        if (profile) {
            mk_mem_free(profile);
            profile = NULL;
        }
        if (key) {
            mk_mem_free(key);
            key = NULL;
        }
        line = strtok(NULL, "\n");
    }
    if (!found_profile) {
        flb_errno();
        res = -1;
    }

    flb_sds_destroy(content);
    if (profile) {
        mk_mem_free(profile);
    }
    if (key) {
        mk_mem_free(key);
    }
    return res;
}

/*
 * Authorization: Signature version="1",keyId="<tenancy_ocid>/<user_ocid>/<key_fingerprint>",
 * algorithm="rsa-sha256",headers="(request-target) date x-content-sha256 content-type content-length",
 * signature="signature"
 */
flb_sds_t create_authorization_header_content(flb_sds_t key_id,
                                              flb_sds_t signature)
{
    flb_sds_t content;

    content = flb_sds_create_size(512);
    flb_sds_cat_safe(&content, FLB_OCI_SIGN_SIGNATURE_VERSION,
                     sizeof(FLB_OCI_SIGN_SIGNATURE_VERSION) - 1);
    flb_sds_cat_safe(&content, ",", 1);
    flb_sds_cat_safe(&content, FLB_OCI_SIGN_KEYID,
                     sizeof(FLB_OCI_SIGN_KEYID) - 1);
    flb_sds_cat_safe(&content, "=\"", 2);
    flb_sds_cat_safe(&content, key_id, flb_sds_len(key_id));
    flb_sds_cat_safe(&content, "\",", 2);
    flb_sds_cat_safe(&content, FLB_OCI_SIGN_ALGORITHM,
                     sizeof(FLB_OCI_SIGN_ALGORITHM) - 1);
    flb_sds_cat_safe(&content, ",", 1);
    flb_sds_cat_safe(&content, FLB_OCI_SIGN_HEADERS,
                     sizeof(FLB_OCI_SIGN_HEADERS) - 1);
    flb_sds_cat_safe(&content, ",", 1);
    flb_sds_cat_safe(&content, FLB_OCI_SIGN_SIGNATURE,
                     sizeof(FLB_OCI_SIGN_SIGNATURE) - 1);
    flb_sds_cat_safe(&content, "=\"", 2);
    flb_sds_cat_safe(&content, signature, flb_sds_len(signature));
    flb_sds_cat_safe(&content, "\"", 1);

    return content;
}

flb_sds_t create_base64_sha256_signature(flb_sds_t private_key,
                                         flb_sds_t signing_string,
                                         struct flb_output_instance *ins)
{
    int len = 0, ret;
    size_t outlen;
    flb_sds_t signature;
    unsigned char sha256_buf[32] = { 0 };
    unsigned char sig[256] = { 0 };
    size_t sig_len = sizeof(sig);

    ret = flb_hash_simple(FLB_HASH_SHA256,
                          (unsigned char*) signing_string,
                          flb_sds_len(signing_string),
                          sha256_buf, sizeof(sha256_buf));

    if(ret != FLB_CRYPTO_SUCCESS) {
        flb_plg_error(ins, "error generating hash buffer");
        return NULL;
    }

    ret =   flb_crypto_sign_simple(FLB_CRYPTO_PRIVATE_KEY,
                                   FLB_CRYPTO_PADDING_PKCS1,
                                   FLB_HASH_SHA256,
                                   (unsigned char *) private_key,
                                   flb_sds_len(private_key),
                                   sha256_buf, sizeof(sha256_buf),
                                   sig, &sig_len);


    if (ret != FLB_CRYPTO_SUCCESS) {
        flb_plg_error(ins, "error signing SHA256");
        return NULL;
    }

    signature = flb_sds_create_size(512);
    if (!signature) {
        flb_errno();
        return NULL;
    }

    /* base 64 encode */
    len = flb_sds_alloc(signature) - 1;
    flb_base64_encode((unsigned char*) signature, len, &outlen, sig,
                      sizeof(sig));
    signature[outlen] = '\0';
    flb_sds_len_set(signature, outlen);

    return signature;
}

flb_sds_t get_date(void)
{

    flb_sds_t rfc1123date;
    time_t t;
    size_t size;
    struct tm tm = { 0 };

    /* Format Date */
    rfc1123date = flb_sds_create_size(32);
    if (!rfc1123date) {
        flb_errno();
        return NULL;
    }

    t = time(NULL);
    if (!gmtime_r(&t, &tm)) {
        flb_errno();
        flb_sds_destroy(rfc1123date);
        return NULL;
    }
    size = strftime(rfc1123date, flb_sds_alloc(rfc1123date) - 1,
                    "%a, %d %b %Y %H:%M:%S GMT", &tm);
    if (size <= 0) {
        flb_errno();
        flb_sds_destroy(rfc1123date);
        return NULL;
    }
    flb_sds_len_set(rfc1123date, size);
    return rfc1123date;
}

flb_sds_t add_header_and_signing(struct flb_http_client *c,
                                        flb_sds_t signing_str, const char *header, int headersize,
                                        const char *val, int val_size)
{
    if (!signing_str) {
        return NULL;
    }

    flb_http_add_header(c, header, headersize, val, val_size);

    flb_sds_cat_safe(&signing_str, "\n", 1);
    flb_sds_cat_safe(&signing_str, header, headersize);
    flb_sds_cat_safe(&signing_str, ": ", 2);
    flb_sds_cat_safe(&signing_str, val, val_size);

    return signing_str;
}

int build_headers(struct flb_http_client *c, flb_sds_t private_key,
                  flb_sds_t key_id, flb_sds_t json, flb_sds_t hostname,
                  int port, flb_sds_t uri, struct flb_output_instance *ins)
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

    /* Add (requeset-target) to signing string */
    encoded_uri = flb_uri_encode(uri, flb_sds_len(uri));
    if (!encoded_uri) {
        flb_errno();
        goto error_label;
    }
    flb_sds_cat_safe(&signing_str, FLB_OCI_HEADER_REQUEST_TARGET,
                     sizeof(FLB_OCI_HEADER_REQUEST_TARGET) - 1);
    flb_sds_cat_safe(&signing_str, ": post ", sizeof(": post ") - 1);
    flb_sds_cat_safe(&signing_str, encoded_uri,
                     flb_sds_len(encoded_uri));

    /* Add Host to Header */
    if (((c->flags & FLB_IO_TLS) && c->port == 443)
        || (!(c->flags & FLB_IO_TLS) && c->port == 80)) {
        /* default port */
        tmp_ref = flb_sds_copy(tmp_sds, c->host, strlen(c->host));
    }
    else {
        tmp_ref = flb_sds_printf(&tmp_sds, "%s:%i", c->host, c->port);
    }
    if (!tmp_ref) {
        flb_plg_error(ins, "cannot compose temporary host header");
        goto error_label;
    }
    tmp_sds = tmp_ref;
    tmp_ref = NULL;

    signing_str = add_header_and_signing(c, signing_str, FLB_OCI_HEADER_HOST,
                                         sizeof(FLB_OCI_HEADER_HOST) - 1,
                                         tmp_sds, flb_sds_len(tmp_sds));
    if (!signing_str) {
        flb_plg_error(ins, "cannot compose signing string");
        goto error_label;
    }

    /* Add Date header */
    rfc1123date = get_date();
    if (!rfc1123date) {
        flb_plg_error(ins, "cannot compose temporary date header");
        goto error_label;
    }
    signing_str = add_header_and_signing(c, signing_str, FLB_OCI_HEADER_DATE,
                                         sizeof(FLB_OCI_HEADER_DATE) - 1, rfc1123date,
                                         flb_sds_len(rfc1123date));
    if (!signing_str) {
        flb_plg_error(ins, "cannot compose signing string");
        goto error_label;
    }

    /* Add x-content-sha256 Header */
    ret = flb_hash_simple(FLB_HASH_SHA256,
                          (unsigned char*) json,
                          flb_sds_len(json),
                          sha256_buf, sizeof(sha256_buf));

    if (ret != FLB_CRYPTO_SUCCESS) {
        flb_plg_error(ins, "error forming hash buffer for x-content-sha256 Header");
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
        flb_plg_error(ins, "cannot compose signing string");
        goto error_label;
    }

    /* Add content-Type */
    signing_str = add_header_and_signing(c, signing_str,
                                         FLB_OCI_HEADER_CONTENT_TYPE, sizeof(FLB_OCI_HEADER_CONTENT_TYPE) - 1,
                                         FLB_OCI_HEADER_CONTENT_TYPE_VAL,
                                         sizeof(FLB_OCI_HEADER_CONTENT_TYPE_VAL) - 1);
    if (!signing_str) {
        flb_plg_error(ins, "cannot compose signing string");
        goto error_label;
    }

    /* Add content-Length */
    tmp_len = snprintf(tmp_sds, flb_sds_alloc(tmp_sds) - 1, "%i",
                       (int) flb_sds_len(json));
    flb_sds_len_set(tmp_sds, tmp_len);
    signing_str = add_header_and_signing(c, signing_str,
                                         FLB_OCI_HEADER_CONTENT_LENGTH, sizeof(FLB_OCI_HEADER_CONTENT_LENGTH) - 1,
                                         tmp_sds, flb_sds_len(tmp_sds));
    if (!signing_str) {
        flb_plg_error(ins, "cannot compose signing string");
        goto error_label;
    }

    /* Add Authorization header */
    signature = create_base64_sha256_signature(private_key, signing_str, ins);
    if (!signature) {
        flb_plg_error(ins, "cannot compose signing signature");
        goto error_label;
    }

    auth_header_str = create_authorization_header_content(key_id, signature);
    if (!auth_header_str) {
        flb_plg_error(ins, "cannot compose authorization header");
        goto error_label;
    }

    flb_http_add_header(c, FLB_OCI_HEADER_AUTH, sizeof(FLB_OCI_HEADER_AUTH) - 1,
                        auth_header_str, flb_sds_len(auth_header_str));

    /* User-Agent */
    flb_http_add_header(c, FLB_OCI_HEADER_USER_AGENT,
                        sizeof(FLB_OCI_HEADER_USER_AGENT) - 1,
                        FLB_OCI_HEADER_USER_AGENT_VAL,
                        sizeof(FLB_OCI_HEADER_USER_AGENT_VAL) - 1);

    /* Accept */
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
