//author Dimitrios Zerkelidis

#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <string.h>
#include <arpa/inet.h> /* For htonl() */


void open_env(FILE *rsa_pkey_file, FILE *in_file, FILE *out_file)
{

    RSA *rsa_pkey = NULL;
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_CIPHER_CTX ctx;
    unsigned char buffer[1024];
    unsigned char buffer_out[1024 + EVP_MAX_IV_LENGTH];
    size_t len;
    int len_out;
    unsigned char *ek;
    unsigned int eklen;
    uint32_t eklen_n;
    unsigned char iv[EVP_MAX_IV_LENGTH];

    PEM_read_RSAPrivateKey(rsa_pkey_file, &rsa_pkey, NULL, NULL);


    EVP_PKEY_assign_RSA(pkey, rsa_pkey);

    EVP_CIPHER_CTX_init(&ctx);
    ek =(  unsigned char *) malloc(EVP_PKEY_size(pkey));

    /* First need to fetch the encrypted key length, encrypted key and IV */

  fread(&eklen_n, sizeof eklen_n, 1, in_file);
  eklen = ntohl(eklen_n);
  fread(ek, eklen, 1, in_file);
  fread(iv, EVP_CIPHER_iv_length(EVP_aes_128_cbc()), 1, in_file);
  EVP_OpenInit(&ctx, EVP_aes_128_cbc(), ek, eklen, iv, pkey);

    while ((len = fread(buffer, 1, sizeof buffer, in_file)) > 0)
    {
        EVP_OpenUpdate(&ctx, buffer_out, &len_out, buffer, len);
        fwrite(buffer_out, len_out, 1, out_file);
    }


    EVP_OpenFinal(&ctx, buffer_out, &len_out);

    fwrite(buffer_out, len_out, 1, out_file);

    EVP_PKEY_free(pkey);
    free(ek);

}

int main(int argc, char *argv[])
{
    FILE *rsa_pkey_file=fopen("privkey.pem", "rb");
    FILE *fp1=fopen("encrypted.txt", "rb");
    FILE *fp2=fopen("decrypted.txt", "wb");


    open_env(rsa_pkey_file, fp1, fp2);

    fclose(rsa_pkey_file);
    fclose(fp1);
    fclose(fp2);
    return 0;
}
