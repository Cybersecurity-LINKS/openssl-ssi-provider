/* OP_KEYMGMT */
extern const OSSL_DISPATCH ossl_vc_keymgmt_functions[];
extern const OSSL_DISPATCH ossl_did_keymgmt_functions[];

/* OP_ENCODER */
extern const OSSL_DISPATCH ossl_vc_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH ossl_did_to_PrivateKeyInfo_pem_encoder_functions[];

/* OP_DECODER */
extern const OSSL_DISPATCH ossl_PrivateKeyInfo_der_to_did_decoder_functions[];