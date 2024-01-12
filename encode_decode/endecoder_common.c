#include "endecoder_local.h"

int read_der(PROV_CTX *provctx, OSSL_CORE_BIO *cin,  char **data,
                  long *len) 
{
    int ok;
    unsigned char *d = malloc(2000);
    size_t l = 0;
    
    BIO *in = ossl_bio_new_from_core_bio(provctx, cin);
    if (in == NULL)
        return 0;
    ok = BIO_read_ex(in, d, 2000, &l);
    if (ok) {
        d[l] = '\0';
        *data = d;
        printf("%s\n", *data);
        *len = l;
    }
    BIO_free(in);
    return ok;      
}