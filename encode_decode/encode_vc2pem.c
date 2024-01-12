# include <openssl/core.h>
# include <openssl/core_dispatch.h>
# include <openssl/crypto.h>
# include <openssl/bio.h>
# include <openssl/pem.h>
//#include "../common/include/prov/provider_ctx.h"
# include "../common/include/prov/bio.h"
# include "../keymgmt/ssi.h"

static OSSL_FUNC_encoder_newctx_fn vc2pem_newctx;
static OSSL_FUNC_encoder_freectx_fn vc2pem_freectx;
static OSSL_FUNC_encoder_encode_fn vc_to_PrivateKeyInfo_pem_encode;
static OSSL_FUNC_encoder_encode_fn vc_to_SubjectPublicKeyInfo_pem_encode;

struct vc2pem_ctx_st {
    PROV_CTX *provctx;
};

static void *vc2pem_newctx(void *provctx)
{   
    printf("VC ctx new\n");
    struct vc2pem_ctx_st *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL) {
        ctx->provctx = provctx;
    }

    return ctx;
}

static void vc2pem_freectx(void *vctx)
{
    struct vc2pem_ctx_st *ctx = vctx;
    printf("VC ctx free\n");

    //TODO

    OPENSSL_free(ctx);
}

static int vc_to_PrivateKeyInfo_pem_encode(void *ctx, OSSL_CORE_BIO *cout, const void *key, const OSSL_PARAM key_abstract[], int selection, OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{   
    struct vc2pem_ctx_st *vcctx = ctx;
    const struct identity *i = key;
    const char *did_document = get_did(i->did);
    printf("I am:\n%s\n", did_document);

    BIO *out = ossl_bio_new_from_core_bio(vcctx->provctx, cout);

    PEM_write_bio(out, "PRIVATE KEY", NULL, (const unsigned char *)did_document, strlen(did_document));
    return 1;                                                           
}

static int vc_to_SubjectPublicKeyInfo_pem_encode(void *ctx, OSSL_CORE_BIO *cout, const void *key, const OSSL_PARAM key_abstract[], int selection, OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg) {

    struct vc2pem_ctx_st *vcctx = ctx;
    const struct identity *i = key;
    const char *vc = get_vc(i->vc);
    printf("I am:\n%s\n", vc);

    BIO *out = ossl_bio_new_from_core_bio(vcctx->provctx, cout);

    PEM_write_bio(out, "PUBLIC KEY", NULL, (const unsigned char *)vc, strlen(vc));
    return 1;
}

const OSSL_DISPATCH ossl_vc_to_PrivateKeyInfo_pem_encoder_functions[] = {           
        { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))vc2pem_newctx },                                 
        { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))vc2pem_freectx },
        { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))vc_to_PrivateKeyInfo_pem_encode },          
        OSSL_DISPATCH_END
};

const OSSL_DISPATCH ossl_vc_to_SubjectPublicKeyInfo_pem_encoder_functions[] = {
        { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))vc2pem_newctx },                                 
        { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))vc2pem_freectx },
        { OSSL_FUNC_ENCODER_ENCODE, (void(*)(void))vc_to_SubjectPublicKeyInfo_pem_encode },          
        OSSL_DISPATCH_END
};
