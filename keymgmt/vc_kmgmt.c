static OSSL_FUNC_keymgmt_new_fn vc_new;
static OSSL_FUNC_keymgmt_load_fn vc_load;
static OSSL_FUNC_keymgmt_gen_init_fn vc_gen_init;
static OSSL_FUNC_keymgmt_gen_fn vc_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn vc_gen_cleanup;
static OSSL_FUNC_keymgmt_has_fn vc_has;

static void *vc_new(void *provctx)
{
    //NULL
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
    //TODO
    return NULL;
}

static void *vc_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    //TODO
    return NULL;
}

static void vc_gen_cleanup(void *genctx)
{
    //TODO
    return NULL;
}

static int vc_has(const void *keydata, int selection)
{
    //TODO
    return NULL;
}
