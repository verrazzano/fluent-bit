set(src
    oci_logging.c
    oci_logging_conf.c
)

FLB_PLUGIN(out_oracle_logging "${src}" "")
