#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>
#include <string.h>
#include "/home/pirug/Desktop/identity-cbindings/header-binding/identity.h"


static OSSL_FUNC_keymgmt_new_fn vc_newdata;
static OSSL_FUNC_keymgmt_gen_init_fn vc_gen_init;
static OSSL_FUNC_keymgmt_gen_fn vc_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn vc_gen_cleanup;
static OSSL_FUNC_keymgmt_load_fn vc_load;
static OSSL_FUNC_keymgmt_has_fn vc_has;
static OSSL_FUNC_keymgmt_free_fn vc_freedata;

struct vc_gen_ctx {
    OSSL_LIB_CTX *libctx;
};

static void *vc_newdata(void *provctx)
{
    //OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    return NULL;
}

static void *vc_load(const void *reference, size_t reference_sz)
{
    // VC *vc = NULL;

    // if (ossl_prov_is_running() && reference_sz == sizeof(vc)) {
    //     /* The contents of the reference is the address to our object */
    //     vc = *(VC **)reference;
    //     /* We grabbed, so we detach it */
    //     *(VC **)reference = NULL;
    //     return vc;
    // }
    return NULL;
}

static void *vc_gen_init(void *provctx, int selection,
                          const OSSL_PARAM params[])
{
    //OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    struct vc_gen_ctx *gctx = NULL;

    if((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        //gctx->libctx = libctx;
    }
    return gctx;
}

static void *vc_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    struct vc_gen_ctx *gctx = genctx;
    char *s = malloc(15 + 1);
    strcpy(s, "Hello mom");
    return s;
}

static void vc_gen_cleanup(void *genctx)
{
    struct vc_gen_ctx *gctx = genctx;

    if(gctx == NULL)
        return;
    OPENSSL_free(gctx);
}

static void vc_freedata(void *keydata)
{
    //TODO
    return;
}

static int vc_has(const void *keydata, int selection)
{
    //TODO
    return 1;
}

const OSSL_DISPATCH ossl_vc_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))vc_newdata },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))vc_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))vc_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))vc_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))vc_load },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))vc_has },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))vc_freedata },
    OSSL_DISPATCH_END
};