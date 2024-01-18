/* OP_KEYMGMT */
extern const OSSL_DISPATCH ossl_vc_keymgmt_functions[];
extern const OSSL_DISPATCH ossl_did_keymgmt_functions[];

/* OP_ENCODER */
extern const OSSL_DISPATCH ossl_vc_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH ossl_vc_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH ossl_vc_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH ossl_did_to_PrivateKeyInfo_pem_encoder_functions[];

/* OP_DECODER */
extern const OSSL_DISPATCH ossl_PrivateKeyInfo_der_to_did_decoder_functions[];
extern const OSSL_DISPATCH ossl_PrivateKeyInfo_der_to_vc_decoder_functions[];
extern const OSSL_DISPATCH ossl_SubjectPublicKeyInfo_der_to_vc_decoder_functions[];

/* OP_SIGNA[TURE */
extern const OSSL_DISPATCH ossl_vc_signature_functions[];