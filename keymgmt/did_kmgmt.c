#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>
#include <string.h>
#include "../common/include/prov/provider_ctx.h"
//#include "/home/pirug/Desktop/identity-cbindings/header-binding/identity.h"

static OSSL_FUNC_keymgmt_new_fn did_newdata;
static OSSL_FUNC_keymgmt_gen_init_fn did_gen_init;
static OSSL_FUNC_keymgmt_gen_fn did_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn did_gen_cleanup;
static OSSL_FUNC_keymgmt_load_fn did_load;
static OSSL_FUNC_keymgmt_has_fn did_has;
static OSSL_FUNC_keymgmt_free_fn did_freedata;

struct did_gen_ctx {
    OSSL_LIB_CTX *libctx;
    Wallet *w;
};

static void *did_newdata(void *provctx)
{
    // TODO
    return NULL;
}

static void *did_load(const void *reference, size_t reference_sz)
{   
	Did *did = NULL;
    char *fragment = OPENSSL_zalloc(reference_sz);
    char *did_document = OPENSSL_zalloc(reference_sz);
    printf("%s\n", (const char*)reference);

    if(sscanf((const char*)reference, "%[^:]:%s", fragment, did_document) == EOF)
    	return NULL;
    did = set_did(did_document, fragment);

    OPENSSL_free(fragment);
    OPENSSL_free(did_document);

    return did;
}

static void *did_gen_init(void *provctx, int selection,
                          const OSSL_PARAM params[])
{
    OSSL_LIB_CTX *libctx = ossl_prov_ctx_get0_libctx(provctx);
    Wallet *w = prov_ctx_get_wallet(provctx);
    struct did_gen_ctx *gctx = NULL;

    if((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        gctx->libctx = libctx;
        gctx->w = w;
    }
    return gctx;
}

static void *did_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    struct did_gen_ctx *gctx = genctx;
    Did *did = NULL;
    
    did = did_create(gctx->w);
    return did;
}

static void did_gen_cleanup(void *genctx)
{
    struct did_gen_ctx *gctx = genctx;

    if(gctx == NULL)
        return;
    OPENSSL_free(gctx);
}

static void did_freedata(void *keydata)
{
    //TODO
    return;
}

static int did_has(const void *keydata, int selection)
{
    //TODO
    return 1;
}

const OSSL_DISPATCH ossl_did_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))did_newdata },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))did_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))did_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))did_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))did_load },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))did_has },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))did_freedata },
    OSSL_DISPATCH_END
};
