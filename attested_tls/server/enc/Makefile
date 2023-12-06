# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

GSL:=../../gsl-oe
GSL_HIST_LINK:=${GSL}/histogram/.libs
GSL_ERR_LINK:=${GSL}/err/.libs
GSL_LINALG_LINK:=${GSL}/linalg/.libs
GSL_FIT_LINK:=${GSL}/fit/.libs
GSL_FLAGS:=-lgslhistogram -lgslerr -lgsllinalg -lgslfit

include ../../../config.mk

ifeq ($(OE_CRYPTO_LIB),openssl_3)
	CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --variable=${OE_CRYPTO_LIB}flags)
	CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --variable=${OE_CRYPTO_LIB}flags)
else
	CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --cflags)
	CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
endif
LDFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --libs)
INCDIR=$(shell pkg-config oeenclave-$(C_COMPILER) --variable=includedir)
CRYPTO_LDFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --variable=${OE_CRYPTO_LIB}libs)

.PHONY: all build clean run

SRC_FILES = ecalls.cpp mbedtls_server.cpp cert_verify_config.cpp ../../common/identity_verifier.cpp ../../common/cert_verifier.cpp ../../common/utility.cpp ../../common/mbedtls_utility.cpp
OBJ_FILES = ecalls.o mbedtls_server.o cert_verify_config.o cert_verifier.o identity_verifier.o utility.o mbedtls_utility.o tls_server_t.o

# Cover openssl, openssl_symcrypt_fips, and openssl_3
ifneq (,$(findstring openssl,$(OE_CRYPTO_LIB)))
	SRC_FILES = ecalls.cpp openssl_server.cpp cert_verify_config.cpp ../../common/verify_callback.cpp ../../common/utility.cpp ../../common/openssl_utility.cpp
	OBJ_FILES = ecalls.o openssl_server.o cert_verify_config.o verify_callback.o utility.o openssl_utility.o tls_server_t.o
endif

EDL_USE_HOST_ENTROPY =

ifeq (${OE_CRYPTO_LIB}, openssl_symcrypt_fips)
	OBJ_FILES += libsymcrypt.so.103
	EDL_USE_HOST_ENTROPY = -DEDL_USE_HOST_ENTROPY
endif

all:
	$(MAKE) build
	$(MAKE) sign

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../tls_server.edl --trusted \
		--trusted-dir . \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx \
		$(EDL_USE_HOST_ENTROPY)


	echo "GSL HIST LINK:" ${GSL_HIST_LINK}
	$(CXX) -L${GSL_HIST_LINK} -I../../gsl/histogram -I../../gsl/fit -I../../gsl-oe -L${GSL_LINALG_LINK} -L${GSL_FIT_LINK} -g -c $(CXXFLAGS) $(INCLUDES) -I. -std=c++11 -Wdate-time ${SRC_FILES}
	#$(CXX) -L${GSL_LINK} -L${GSL_LINALG_LINK} -L${GSL_FIT_LINK} ${LIB_GSL} -I/home/azureuser/openenclave/samples/gsl/histogram -g -I/home/azureuser/openenclave/samples/confidential_compute/gsl-github/ -c $(CXXFLAGS) $(INCLUDES) -I. -std=c++11 ${SRC_FILES} ${GSL_FLAGS} -Wl,-rpath,/home/azureuser/openenclave/samples/confidential_compute/libs


	$(CC) -c $(CFLAGS) $(CINCLUDES) -I. -Wdate-time tls_server_t.c
	$(CXX) -o tls_server_enc -L${GSL_HIST_LINK} -I../../gsl/histogram -I../../gsl/fit -L${GSL_LINALG_LINK} -L${GSL_FIT_LINK} -L${GSL_ERR_LINK} $(OBJ_FILES) $(LDFLAGS) $(CRYPTO_LDFLAGS) ${GSL_FLAGS} -loehostsock -loehostresolver -Wdate-time

sign:
	oesign sign -e tls_server_enc -c enc.conf -k private.pem
	oesign dump -e tls_server_enc.signed > temp.dmp
	chmod u+x ../../scripts/gen_mrenclave_header.sh
	../../scripts/gen_mrenclave_header.sh ../../common/tls_server_enc_mrenclave.h temp.dmp
	rm temp.dmp

clean:
	rm -f *.o tls_server_enc tls_server_enc.signed tls_server_enc.signed.so tls_server_t.* tls_server_args.h yy ../../common/tls_server_enc_mrenclave.h
