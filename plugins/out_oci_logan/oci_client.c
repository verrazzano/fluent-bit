//
// Created by Aditya Bharadwaj on 23/07/23.
//

#include "oci_logan.h"
#include "oci_client.h"
#include "oci_logan_conf.h"

#include <fluent-bit/flb_crypto.h>
#include <fluent-bit/flb_hash.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/pem.h>

// get region from region url, tenancy id from leaf certificate
// from the federation endpoint fetch or refresh security token
struct request_signer *build_instance_principal_signer() {
    struct request_signer *rs;
    rs = flb_calloc(1, sizeof(struct request_signer));
    if (!rs) {
        return NULL;
    }

    // retrieve leaf certificate

    // retrieve intermediate certificate

    // get tenancy id from leaf cert

    // get region from region endpoint

    // get security token using a federation client


    return rs;
}

struct cert_retriever *url_based_cert_retriever(flb_sds_t cert_url,
                                                flb_sds_t cert_key_url,
                                                struct flb_upstream *u)
{
    struct cert_retriever *cr;
    cr = flb_calloc(1, sizeof(struct cert_retriever));
    if (!cr) {
        return NULL;
    }

    return cr;

}

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

    priv_key = flb_sds_create_len(c->resp.payload, c->resp.payload_size);

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

    fingerprint = flb_sds_create_len(buf, 3*SHA_DIGEST_LENGTH - 1);

    return fingerprint;
}



