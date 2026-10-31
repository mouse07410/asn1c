/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <ANY.h>

asn_enc_rval_t
ANY_encode_jer(const asn_TYPE_descriptor_t *td, const asn_jer_constraints_t *constraints,
               const void *sptr, int ilevel,
               enum jer_encoder_flags_e flags, asn_app_consume_bytes_f *cb,
               void *app_key) {
  /* Normalize ANY's signed length before invoking the OCTET STRING encoder. */
  OCTET_STRING_t view;
  if(!td || !cb || ANY_to_octet_view((const ANY_t *)sptr, &view))
    ASN__ENCODE_FAILED;
  return OCTET_STRING_encode_jer(td, constraints, &view, ilevel, flags, cb, app_key);
}
