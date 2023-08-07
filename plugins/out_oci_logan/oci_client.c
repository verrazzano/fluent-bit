//
// Created by Aditya Bharadwaj on 23/07/23.
//

#include "oci_logan.h"
#include "oci_client.h"
#include "oci_logan_conf.h"

// get region from region url, tenancy id from leaf certificate
// from the federation endpoint fetch security token
struct request_signer *build_instance_principal_signer() {
    struct request_signer *rs;
    rs = flb_calloc(1, sizeof(struct request_signer));
    if (!rs) {
        return NULL;
    }


    return rs;
}