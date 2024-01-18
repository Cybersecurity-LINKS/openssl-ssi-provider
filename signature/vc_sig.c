# include <openssl/core.h>
# include <openssl/core_dispatch.h>

static OSSL_FUNC_signature_newctx_fn vc_newctx;
static OSSL_FUNC_signature_freectx_fn vc_freectx;

static OSSL_FUNC_signature_digest_sign_init_fn vc_digest_signverify_init;
static OSSL_FUNC_signature_digest_sign_fn vc_digest_sign;

static void *vc_newctx(void *provctx, const char *propq)
{

    return NULL;
}

static void vc_freectx(void *ctx)
{

    return;
}

int vc_digest_signverify_init(void *ctx, const char *mdname,
                                         void *provkey,
                                         const OSSL_PARAM params[]) {

    return 1;
}

int vc_digest_sign(void *ctx,
                             unsigned char *sigret, size_t *siglen,
                             size_t sigsize, const unsigned char *tbs,
                             size_t tbslen) {

    return 1;
}

const OSSL_DISPATCH ossl_vc_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))vc_newctx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))vc_digest_signverify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
      (void (*)(void))vc_digest_sign },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))vc_freectx },
    OSSL_DISPATCH_END
};