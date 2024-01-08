/* #include "endecoder_local.h"

int read_der(PROV_CTX *provctx, OSSL_CORE_BIO *cin,  unsigned char **data,
                  long *len) 
{
    BUF_MEM *mem = NULL;
    BIO *in = ossl_bio_new_from_core_bio(provctx, cin);
    int ok;

    if (in == NULL)
        return 0;
    ok = (asn1_d2i_read_bio(in, &mem) >= 0);
    if (ok) {
        *data = (unsigned char *)mem->data;
        *len = (long)mem->length;
        OPENSSL_free(mem);
    }
    BIO_free(in);
    return ok;
} */