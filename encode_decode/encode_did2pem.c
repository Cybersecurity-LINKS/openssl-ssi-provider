#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include "../common/include/prov/provider_ctx.h"
#include "../common/include/prov/bio.h"

static OSSL_FUNC_encoder_newctx_fn did2pem_newctx;
static OSSL_FUNC_encoder_freectx_fn did2pem_freectx;
static OSSL_FUNC_encoder_encode_fn did_to_PrivateKeyInfo_pem_encode;

struct did2pem_ctx_st {
    PROV_CTX *provctx;
};

static void *did2pem_newctx(void *provctx)
{   
    printf("DID ENCODER ctx new\n");
    struct did2pem_ctx_st *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL) {
        ctx->provctx = provctx;
    }

    return ctx;
}

static void did2pem_freectx(void *vctx)
{
    struct did2pem_ctx_st *ctx = vctx;
    printf("DID ctx free\n");

    //TODO

    OPENSSL_free(ctx);
}

static int did_to_PrivateKeyInfo_pem_encode(void *ctx, OSSL_CORE_BIO *cout, const void *key, const OSSL_PARAM key_abstract[], int selection, OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{   
    struct did2pem_ctx_st *didctx = ctx;
    const Did *did = key;
    const char *did_document = get_did(did);
    printf("I am:\n%s\n", did_document);

    BIO *out = ossl_bio_new_from_core_bio(didctx->provctx, cout);

    PEM_write_bio(out, "PRIVATE KEY", NULL, (const unsigned char *)did_document, strlen(did_document));                                                           
    return 1;                                                           
}

const OSSL_DISPATCH ossl_did_to_PrivateKeyInfo_pem_encoder_functions[] = {           
        { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))did2pem_newctx },                                 
        { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))did2pem_freectx },
        { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))did_to_PrivateKeyInfo_pem_encode },           
        OSSL_DISPATCH_END
};