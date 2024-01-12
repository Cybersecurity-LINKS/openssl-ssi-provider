#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include "../common/include/prov/bio.h"
#include "endecoder_local.h"
#include <openssl/core_object.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include "../names.h"
#include <string.h>

static OSSL_FUNC_decoder_newctx_fn der2vc_newctx;
static OSSL_FUNC_decoder_freectx_fn der2vc_freectx;
static OSSL_FUNC_decoder_decode_fn PrivateKeyInfo_der_to_vc_decode;
static OSSL_FUNC_decoder_decode_fn SubjectPublicKeyInfo_der_to_vc_decode;

struct der2vc_ctx_st {
    PROV_CTX *provctx;
};

static void *der2vc_newctx(void *provctx) 
{
    struct der2vc_ctx_st *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if(ctx != NULL) {
        ctx->provctx = provctx;
    }
    
    return ctx;
}

static void der2vc_freectx(void *vctx) 
{
    struct der2vc_ctx_st *ctx = vctx;
    OPENSSL_free(ctx);

    return;
}

static int PrivateKeyInfo_der_to_vc_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
                          OSSL_CALLBACK *data_cb, void *data_cbarg,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg) {
    
    struct der2vc_ctx_st *ctx = vctx;
    char *did_doc = NULL;
    long did_doc_read = 0;
    int ok = 0;
    char oid[20];

    ok = read_der(ctx->provctx, cin, &did_doc, &did_doc_read);
    if(!ok)
        goto next;

    if(sscanf((char *)did_doc, "%s", oid) == EOF)
        goto next;
    
    ok = OPENSSL_strcasecmp(oid, DID_OID);
    if(ok)
        goto next;

    OSSL_PARAM params[4];
    int object_type = OSSL_OBJECT_PKEY;

    params[0] =
        OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = 
        OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                             "VC", 0);
    params[2] =
        OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, did_doc, did_doc_read);

    params[3] = OSSL_PARAM_construct_end();

    ok = data_cb(params, data_cbarg);

    OPENSSL_free(did_doc);
    return ok;

next:
    OPENSSL_free(did_doc);
    return 1;
}

static int SubjectPublicKeyInfo_der_to_vc_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
                          OSSL_CALLBACK *data_cb, void *data_cbarg,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg) {

    struct der2vc_ctx_st *ctx = vctx;
    char *vc = NULL;
    long vc_length = 0;
    int ok = 0;
    char oid[20];

    ok = read_der(ctx->provctx, cin, &vc, &vc_length);
    if(!ok)
        goto next;

    if(sscanf((char *)vc, "%s", oid) == EOF)
        goto next;
    
    ok = OPENSSL_strcasecmp(oid, VC_OID);
    if(ok)
        goto next;

    OSSL_PARAM params[4];
    int object_type = OSSL_OBJECT_PKEY;

    params[0] =
        OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = 
        OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                             "VC", 0);
    params[2] =
        OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, vc, vc_length);

    params[3] = OSSL_PARAM_construct_end();

    ok = data_cb(params, data_cbarg);

    OPENSSL_free(vc);
    return ok;

next:
    OPENSSL_free(vc);
    return 1;
}

const OSSL_DISPATCH ossl_PrivateKeyInfo_der_to_vc_decoder_functions[] = {           
        { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))der2vc_newctx },                                 
        { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))der2vc_freectx },
        { OSSL_FUNC_DECODER_DECODE, (void (*)(void))PrivateKeyInfo_der_to_vc_decode },           
        OSSL_DISPATCH_END
};

const OSSL_DISPATCH ossl_SubjectPublicKeyInfo_der_to_vc_decoder_functions[] = {           
        { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))der2vc_newctx },                                 
        { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))der2vc_freectx },
        { OSSL_FUNC_DECODER_DECODE, (void (*)(void))SubjectPublicKeyInfo_der_to_vc_decode },           
        OSSL_DISPATCH_END
};