set(src
   oci_logan.c
   oci_logan_conf.c
   oci_client.c
   )

FLB_PLUGIN(out_oci_logan "${src}" "")
