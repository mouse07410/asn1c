#ifndef	ASN1C_SAVE_H
#define	ASN1C_SAVE_H

int asn1c_save_compiled_output(arg_t *arg, const char *datadir, const char* destdir,
	int argc, int optc, char **argv);

/* Check if a typename is in the PDU list (for -pdu=Type) */
int asn1c__pdu_type_lookup(const char *typename);

#endif	/* ASN1C_SAVE_H */
