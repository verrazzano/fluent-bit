//
// Created by Aditya Bharadwaj on 16/10/23.
//

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_config.h>
#include "oci_logging_conf.h"
#include "oci_logging.h"

struct flb_oci_logging *flb_oci_logging_conf_create(struct flb_output_instance *ins,
                                                    struct flb_config *config)
{
    struct flb_oci_logging *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_oci_logging));

    return ctx;
}

int flb_oci_logging_conf_destroy(struct flb_oci_logging *ctx)
{
    return 0;
}