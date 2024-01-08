#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_object.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include "../common/include/prov/bio.h"
//#include <string.h>
#include <openssl/buffer.h>
#include <openssl/err.h>

static OSSL_FUNC_decoder_newctx_fn der2did_newctx;
static OSSL_FUNC_decoder_freectx_fn der2did_freectx;
static OSSL_FUNC_decoder_decode_fn PrivateKeyInfo_der_to_did_decode;

struct der2did_ctx_st {
    PROV_CTX *provctx;
};

static int read_did(PROV_CTX *provctx, OSSL_CORE_BIO *cin,  char **did_doc,
                  long *did_doc_len)
{
    int ok;
    char *data = malloc(2000);
    size_t length = 0;

    /* BUF_MEM *mem = NULL;
    mem = BUF_MEM_new();
    if (mem == NULL) {
        ERR_raise(ERR_LIB_ASN1, ERR_R_BUF_LIB);
        return -1;
    } */
    
    BIO *in = ossl_bio_new_from_core_bio(provctx, cin);
    if (in == NULL)
        return 0;
    ok = BIO_read_ex(in, data, 2000, &length);
    if (ok) {
        *did_doc = data;
        printf("%s\n", *did_doc);
        *did_doc_len = length;
        /* OPENSSL_free(mem); */
    }
    BIO_free(in);
    return ok;
} 

static void *der2did_newctx(void *provctx)
{
    printf("DID DECODER ctx new\n");
    struct der2did_ctx_st *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL) {
        ctx->provctx = provctx;
    }

    return ctx;
}

static void der2did_freectx(void *vctx)
{
    struct der2did_ctx_st *ctx = vctx;
    OPENSSL_free(ctx);
}

static int PrivateKeyInfo_der_to_did_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
                          OSSL_CALLBACK *data_cb, void *data_cbarg,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    struct der2did_ctx_st *ctx = vctx;
    char *did_doc = NULL;
    long did_doc_read = 0;
    int ok = 0;

    /* char s[] = "Ciao";

    BIO *in = ossl_bio_new_from_core_bio(ctx->provctx, cin);

    if(in == NULL)
        return ok;

    if(!BIO_read_ex(in, &did_doc, 2000, &did_doc_read))
        return ok;
    printf("Size of DID Document: %ld bytes \n", did_doc_read);

    BIO_free(in); */

    /* if(!ossl_prov_bio_read_ex(cin, &did_doc, 1218, &did_doc_read))
        return ok;
    printf("Size of DID Document: %ld bytes \n", did_doc_read); */

    ok = read_did(ctx->provctx, cin, &did_doc, &did_doc_read);
    if(!ok)
        return ok;

    OSSL_PARAM params[4];
    int object_type = OSSL_OBJECT_PKEY;

    params[0] =
        OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = 
        OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                             "DID", 0);
    params[2] =
        OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, did_doc, did_doc_read);

    params[3] = OSSL_PARAM_construct_end();

    ok = data_cb(params, data_cbarg);

    OPENSSL_free(did_doc);
    return ok;
}

const OSSL_DISPATCH ossl_PrivateKeyInfo_der_to_did_decoder_functions[] = {           
        { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))der2did_newctx },                                 
        { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))der2did_freectx },
        { OSSL_FUNC_DECODER_DECODE, (void (*)(void))PrivateKeyInfo_der_to_did_decode },           
        OSSL_DISPATCH_END
};
