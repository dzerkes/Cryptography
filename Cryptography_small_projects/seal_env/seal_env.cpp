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


void envelope_seal(FILE *rsa_pkey_file, FILE *in_file, FILE *out_file) //pubkey , fp2 , fp3
{
   RSA *rsa_pkey = NULL;
   EVP_PKEY *pkey = EVP_PKEY_new();
   EVP_CIPHER_CTX ctx;
   unsigned char buffer[1024];
   unsigned char buffer_out[1024 + EVP_MAX_IV_LENGTH];
   size_t len;
   int len_out;
   unsigned char *ek;
   int eklen;
   uint32_t eklen_n;
   unsigned char iv[EVP_MAX_IV_LENGTH];
   PEM_read_RSA_PUBKEY(rsa_pkey_file, &rsa_pkey, NULL, NULL);
   EVP_PKEY_assign_RSA(pkey, rsa_pkey);

   EVP_CIPHER_CTX_init(&ctx);
   ek =(unsigned char *) malloc(EVP_PKEY_size(pkey));

   EVP_SealInit(&ctx, EVP_aes_128_cbc(), &ek, &eklen, iv, &pkey, 1);
   eklen_n = htonl(eklen);
   fwrite(&eklen_n, sizeof eklen_n, 1, out_file);
   fwrite(ek, eklen, 1, out_file);
   fwrite(iv, EVP_CIPHER_iv_length(EVP_aes_128_cbc()), 1, out_file);

   ///////
   while ((len = fread(buffer, 1, sizeof buffer, in_file)) > 0)
    {
        EVP_SealUpdate(&ctx, buffer_out, &len_out, buffer, len);
        fwrite(buffer_out, len_out, 1, out_file);
        printf("%d",sizeof(buffer_out));
      }
   EVP_SealFinal(&ctx, buffer_out, &len_out);
   fwrite(buffer_out, len_out, 1, out_file);

   EVP_PKEY_free(pkey);
}

int main(){

  FILE *rsa_pkey_file = fopen("pubkey.pem","rb");
  FILE *fp1 = fopen("plaintext.txt","rb");
  FILE *fp2 = fopen("encrypted.txt","wb");
  envelope_seal(rsa_pkey_file,fp1,fp2);

 fclose(rsa_pkey_file);
 fclose(fp1);
 fclose(fp2);
 return  0;
}
