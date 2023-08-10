//
// Created by Aditya Bharadwaj on 23/07/23.
//

#include "oci_client.h"

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_config.h>

#include <fluent-bit/flb_crypto.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <jsmn/jsmn.h>

flb_sds_t refresh_cert(struct flb_upstream *u,
                       flb_sds_t cert_url)
{
    flb_sds_t cert = NULL;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    int ret = 0;
    size_t b_sent;
    u_conn = flb_upstream_conn_get(u);
    if (!u_conn) {
        flb_errno();
        return NULL;
    }

    // TODO: construct cert url

    c = flb_http_client(u_conn, FLB_HTTP_GET, cert_url, NULL, 0,
                        NULL, 0, NULL, 0);

    if (!c) {
        flb_errno();
        flb_upstream_conn_release(u_conn);
        return NULL;
    }
    ret = flb_http_do(c, &b_sent);

    if (!ret) {
        flb_errno();
        flb_upstream_conn_release(u_conn);
        flb_http_client_destroy(c);
        return NULL;
    }

    if (c->resp.status != 200 && c->resp.status != 204 && c->resp.status != 201) {
        flb_errno();
        flb_upstream_conn_release(u_conn);
        flb_http_client_destroy(c);
        return NULL;
    }

    cert = flb_sds_create_len(c->resp.payload, c->resp.payload_size);

    if (!cert) {
        flb_errno();
        flb_upstream_conn_release(u_conn);
        flb_http_client_destroy(c);
        return NULL;
    }

    flb_upstream_conn_release(u_conn);
    flb_http_client_destroy(c);
    return cert;
}

flb_sds_t refresh_cert_key(struct flb_upstream *u,
                           flb_sds_t cert_key_url)
{
    flb_sds_t priv_key = NULL;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    int ret = 0;
    size_t b_sent;
    u_conn = flb_upstream_conn_get(u);
    if (!u_conn) {
        flb_errno();
        return NULL;
    }

    // construct cert key url

    c = flb_http_client(u_conn, FLB_HTTP_GET, cert_key_url, NULL, 0,
                        NULL, 0, NULL, 0);

    if (!c) {
        flb_errno();
        flb_upstream_conn_release(u_conn);
        return NULL;
    }
    ret = flb_http_do(c, &b_sent);

    if (!ret) {
        flb_errno();
        flb_upstream_conn_release(u_conn);
        flb_http_client_destroy(c);
        return NULL;
    }

    if (c->resp.status != 200 && c->resp.status != 204 && c->resp.status != 201) {
        flb_errno();
        flb_upstream_conn_release(u_conn);
        flb_http_client_destroy(c);
        return NULL;
    }

    priv_key = flb_sds_create_len(c->resp.payload, (int) c->resp.payload_size);

    if (!priv_key) {
        flb_errno();
        flb_upstream_conn_release(u_conn);
        flb_http_client_destroy(c);
        return NULL;
    }

    flb_upstream_conn_release(u_conn);
    flb_http_client_destroy(c);
    return priv_key;

}

// finish this func
flb_sds_t get_tenancy_id_from_certificate(X509 *cert)
{
    flb_sds_t t_id = NULL;
    int loc = -1;
    const unsigned char *str;
    char* x;

    X509_NAME *subj = X509_get_subject_name(cert);

    for (int i = 0; i < X509_NAME_entry_count(subj); i++) {
        X509_NAME_ENTRY *e = X509_NAME_get_entry(subj, i);
        ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
        str = ASN1_STRING_get0_data(d);
        x = strstr((const char *) str, "opc-tenant:");
        if (x) {
            break;
        }
    }

    t_id = flb_sds_create((const char*) str + 11);

    return t_id;
}

int sanitize_certificate_string(flb_sds_t *cert_pem)
{
    // i2d_X509()
    char c_start[] = "-----BEGIN CERTIFICATE-----";
    char c_end[] = "-----END CERTIFICATE-----";
    char k_start[] = "-----BEGIN PUBLIC KEY-----";
    char k_end[] = "-----END PUBLIC KEY-----";
    char *start = NULL;

    start = strstr(c_start, *cert_pem);
    strcpy(start, "");

    start = strstr(c_end, *cert_pem);
    strcpy(start, "");

    start = strstr(*cert_pem, k_start);
    strcpy(start, "");

    start = strstr(*cert_pem, k_end);
    strcpy(start,"");

    start = strstr(*cert_pem, "\n");
    while(start != NULL)
    {
        strcpy(start, "");
        start = strstr(*cert_pem, "\n");
    }
    return 0;
}

void colon_separated_fingerprint(unsigned char* readbuf, void *writebuf, size_t len)
{
    char *l;
    for(size_t i=0; i < len-1; i++) {
        l = (char*) (3*i + ((intptr_t) writebuf));
        sprintf(l, "%02x:", readbuf[i]);
    }

    l = (char*) (3*(len - 1) + ((intptr_t) writebuf));
    sprintf(l, "%02x", readbuf[len - 1]);

}

flb_sds_t fingerprint(X509 *cert)
{
    // i2d_X509()
    flb_sds_t fingerprint = NULL;
    const EVP_MD *digest;
    unsigned char md[SHA_DIGEST_LENGTH];
    char buf[3*SHA_DIGEST_LENGTH];
    unsigned int n;

    digest = EVP_get_digestbyname("sha1");
    X509_digest(cert, digest, md, &n);

    colon_separated_fingerprint(md, (void *) buf, (size_t) SHA_DIGEST_LENGTH);

    fingerprint = flb_sds_create_len(buf, 3*SHA_DIGEST_LENGTH);
    return fingerprint;
}

int session_key_supplier(flb_sds_t *priv_key,
                         flb_sds_t *pub_key)
{
    // Key generation
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY* key = NULL;
    BIO *pri, *pub;
    int priKeyLen;
    int pubKeyLen;
    char* priKeyStr;
    char* pubKeyStr;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEYLEN);
    EVP_PKEY_keygen(ctx, &key);
    EVP_PKEY_CTX_free(ctx);

    // Serialize to string
    pri = BIO_new(BIO_s_mem());
    pub = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(pri, key, NULL, NULL, 0, 0, NULL);
    PEM_write_bio_PUBKEY(pub, key);

    priKeyLen = BIO_pending(pri);
    pubKeyLen = BIO_pending(pub);
    priKeyStr = flb_malloc(priKeyLen + 1);
    pubKeyStr = flb_malloc(pubKeyLen + 1);
    BIO_read(pri, priKeyStr, priKeyLen);
    BIO_read(pub, pubKeyStr, pubKeyLen);
    priKeyStr[priKeyLen] = '\0';
    pubKeyStr[pubKeyLen] = '\0';

    *priv_key = flb_sds_create_len((const char *) priKeyStr, priKeyLen);
    *pub_key = flb_sds_create_len((const char *)pubKeyStr, pubKeyLen);

    return 0;
}


flb_sds_t get_region(struct flb_upstream *u)
{
    flb_sds_t security_token;
    struct flb_connection *u_conn;
    char* url;
    struct flb_http_client *c;
    size_t b_sent;
    int ret;

    // TODO: construct region uri
    u_conn = flb_upstream_conn_get(u);
    if (!u_conn) {
        flb_errno();
        return NULL;
    }

    c = flb_http_client(u_conn, FLB_HTTP_GET, url,
                        NULL, 0, NULL, 0, NULL, 0);
    if (!c) {
        flb_errno();
        return NULL;
    }

    flb_http_add_header(c, "Authorization", 13, "Bearer Oracle", 13);

    ret = flb_http_do(c, &b_sent);

    if (ret != 0) {
        return NULL;
    }

    if (c->resp.status != 200 && c->resp.status != 201 &&
        c->resp.status != 204) {
        return NULL;
    }

    security_token = flb_sds_create_len(mk_string_tolower(c->resp.payload),
                                        (int) c->resp.payload_size);

    return security_token;
}

flb_sds_t parse_token(char *response,
                      size_t response_len)
{
    int tok_size = 32, ret, i;
    jsmn_parser parser;
    jsmntok_t *t;
    jsmntok_t *tokens;
    char *key;
    char *val;
    int key_len;
    int val_len;
    flb_sds_t token = NULL;

    jsmn_init(&parser);

    tokens = flb_calloc(1, sizeof(jsmntok_t) * tok_size);
    if (!tokens) {
        flb_errno();
        return NULL;
    }

    ret = jsmn_parse(&parser, response, response_len, tokens, tok_size);

    if (ret<=0) {
        flb_free(tokens);
        return NULL;
    }
    tok_size = ret;

    /* Parse JSON tokens */
    for (i = 0; i < tok_size; i++) {
        t = &tokens[i];

        if (t->start == -1 || t->end == -1 || (t->start == 0 && t->end == 0)) {
            break;
        }

        if (t->type != JSMN_STRING) {
            continue;
        }

        key = response + t->start;
        key_len = (t->end - t->start);

        i++;
        t = &tokens[i];
        val = response + t->start;
        val_len = (t->end - t->start);

        if (val_len < 1) {
            continue;
        }

        if ((key_len == sizeof(FLB_OCI_TOKEN) - 1)
            && strncasecmp(key, FLB_OCI_TOKEN,
                           sizeof(FLB_OCI_TOKEN) - 1) == 0) {
            // code
            token = flb_sds_create_len(val, val_len);
            if (!token) {
                flb_free(tokens);
                return NULL;
            }
            break;
        }
    }

    flb_free(tokens);
    return token;
}
