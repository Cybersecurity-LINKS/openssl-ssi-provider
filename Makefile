OPENSLL_INSTALL_DIR=/home/pirug/openssl
IDENTITY_CBINDINGS=/home/pirug/Desktop/identity-cbindings
OPENSSL_LIB=lib64

CC = gcc
CFLAGS =\
-I $(OPENSLL_INSTALL_DIR)/include/\
-I $(IDENTITY_CBINDINGS)/header-binding/\
-Wl,-rpath=$(IDENTITY_CBINDINGS)/target/debug/\
-L $(IDENTITY_CBINDINGS)/target/debug/\
-Wall -fPIC -g 

LDFLAGS = -shared -lidentity_openssl 

TARGET = libssiprovider.so
SOURCES = keymgmt/ssi.h keymgmt/vc_kmgmt.c keymgmt/did_kmgmt.c\
	encode_decode/endecoder_local.h encode_decode/endecoder_common.c encode_decode/decode_der2vc.c encode_decode/decode_der2did.c encode_decode/encode_vc2pem.c encode_decode/encode_did2pem.c\
	signature/vc_sig.c\
	common/bio_prov.c common/provider_ctx.c common/include/prov/bio.h common/include/prov/provider_ctx.h\
	ssiprov.c names.h
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC)  $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)

clean:
	rm -f ssiprov.o keymgmt/vc_kmgmt.o keymgmt/did_kmgmt.o encode_decode/encode_vc2pem.o encode_decode/encode_did2pem.o common/bio_prov.o common/provider_ctx.o libssiprovider.so

install:
	
	cp libssiprovider.so $(OPENSLL_INSTALL_DIR)/$(OPENSSL_LIB)/ossl-modules/ssi.so

uninstall:
	rm -f $(OPENSLL_INSTALL_DIR)/$(OPENSSL_LIB)/ossl-modules/ssi.so