char * der2pem(const char *what, unsigned char * der, size_t derlen);
int pem2der(unsigned char * buff);

int populate_self_signed(mbedtls_pk_context * key, const char * CN_or_full_DN, mbedtls_x509write_cert * crt);
int sign_and_topem(mbedtls_pk_context * key, mbedtls_x509write_cert * crt,  char ** out_cert_as_pem,  char ** out_key_as_pem);

int fingerprint_from_certpubkey(const mbedtls_x509_crt * crt, unsigned char sha256[256/8]);
int fingerprint_from_pem(char * buff, unsigned char sha256[256 / 8]);

char * sha256toHEX(unsigned char sha256[256 / 8], char buff[256 / 4 + 1]);

// int sign_and_toder(mbedtls_pk_context * key, mbedtls_x509write_cert * crt, unsigned char ** out_cert_as_der, size_t * outcertlenp, unsigned char ** out_key_as_der, size_t * outkeylenp);
