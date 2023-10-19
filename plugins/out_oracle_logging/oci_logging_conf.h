//
// Created by Aditya Bharadwaj on 16/10/23.
//

#ifndef FLB_OUT_ORACLE_LOGGING_CONF_H
#define FLB_OUT_ORACLE_LOGGING_CONF_H

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_config.h>
#include "oci_logging.h"

struct flb_oci_logging *flb_oci_logging_conf_create(struct flb_output_instance *ins,
                                                    struct flb_config *config);
int flb_oci_logging_conf_destroy(struct flb_oci_logging *ctx);

#endif
