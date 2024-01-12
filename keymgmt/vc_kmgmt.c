# include <openssl/core.h>
# include <openssl/core_dispatch.h>
# include <openssl/crypto.h>
# include <string.h>
# include "ssi.h"
# include "../common/include/prov/provider_ctx.h"
# include "../names.h"

static OSSL_FUNC_keymgmt_new_fn vc_newdata;
static OSSL_FUNC_keymgmt_gen_init_fn vc_gen_init;
static OSSL_FUNC_keymgmt_gen_fn vc_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn vc_gen_cleanup;
static OSSL_FUNC_keymgmt_load_fn vc_load;
static OSSL_FUNC_keymgmt_has_fn vc_has;
static OSSL_FUNC_keymgmt_free_fn vc_freedata;

struct vc_gen_ctx {
    OSSL_LIB_CTX *libctx;
    Wallet *w;
};

static void *vc_newdata(void *provctx)
{
    //OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    return NULL;
}

static void *vc_load(const void *reference, size_t reference_sz)
{   
    struct identity *i = NULL;

    char oid[20];
    char *did_document = NULL;
    char *fragment = NULL;
    char *vc_jwt = NULL;

    Vc *vc = NULL;
    Did *did = NULL;

    if(sscanf((const char *)reference, "%s", oid) == EOF)
        return NULL;

    if(OPENSSL_strcasecmp(oid, DID_OID) == 0) {
        did_document = OPENSSL_zalloc(reference_sz);
        fragment = OPENSSL_zalloc(reference_sz);
        sscanf((const char *)reference, "%*s %s %s", fragment, did_document);
        printf("%s %s\n", fragment, did_document);
        did = set_did(did_document, fragment);
    } else if(OPENSSL_strcasecmp(oid, VC_OID) == 0) {
        vc_jwt = OPENSSL_zalloc(reference_sz);
        sscanf((const char *)reference, "%*s %s", vc_jwt);
        printf("VC is %s\n", vc_jwt);
        vc = set_vc((const char *)vc_jwt);
    } else 
        return NULL;

    i = OPENSSL_zalloc(sizeof(*i));
    if(i == NULL)
        return NULL;

    i->did = did;
    i->vc = vc;

    OPENSSL_free(fragment);
    OPENSSL_free(did_document);
    OPENSSL_free(vc_jwt);

    return i;
}

static void *vc_gen_init(void *provctx, int selection,
                          const OSSL_PARAM params[])
{
    OSSL_LIB_CTX *libctx = ossl_prov_ctx_get0_libctx(provctx);
    Wallet *w = prov_ctx_get_wallet(provctx);
    struct vc_gen_ctx *gctx = NULL;

    if((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        gctx->libctx = libctx;
        gctx->w = w;
    }
    return gctx;
}

static void *vc_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    struct vc_gen_ctx *gctx = genctx;
    struct identity *i = NULL;

    i = OPENSSL_zalloc(sizeof(*i));
    if(i == NULL)
        return NULL;

    Did *did = did_create(gctx->w);
    const char *did_document = get_did(did);
    printf("\nDID Document: %s\n", did_document);
    i->did = did;

    Vc *vc = vc_create(gctx->w, did, "www.server.com");
    const char* vc_jwt = get_vc(vc);
    printf("\nVC as JWT:\n %s", vc_jwt);
    i->vc = vc;

    return i;
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
    //TODO liberare identity i
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