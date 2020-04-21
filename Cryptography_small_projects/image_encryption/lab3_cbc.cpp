#include <stdlib.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
#include <fstream>
#include <openssl/err.h>

int main(void) {

  unsigned char pt[1024] = "Text for aes.";  // plaintext
  unsigned char ct[1024 + EVP_MAX_BLOCK_LENGTH];  // ciphertext
  unsigned char key[EVP_MAX_KEY_LENGTH] = "My key";  // encryption and decryption key
  unsigned char iv[EVP_MAX_IV_LENGTH] = "initial vector";  // initialization vector
  const char cipherName[] = "aes-128-cbc";
  const EVP_CIPHER * cipher;

  int ptLength = strlen((const char*) pt);
  int ctLength = 0;
  int tmpLength = 0;
  int res;


  FILE *fileptr;

  fileptr = fopen("Mad_scientist.bmp", "rb");

  OpenSSL_add_all_ciphers();
  /* ciphers and hashes could be loaded using OpenSSL_add_all_algorithms() */

  cipher = EVP_get_cipherbyname(cipherName);
  if(!cipher) {
    printf("Cipher %s not found.\n", cipherName);
    exit(1);
  }

  EVP_CIPHER_CTX *ctx; // context structure
  ctx = EVP_CIPHER_CTX_new();
  if(ctx == NULL) exit(2);

  //printf("pt: %s\n", pt);

  /* Encryption */






 // read HEADER
 unsigned char imagedata[54];
 int bytevalue;
 int index=0;
 if(fileptr != NULL){
   do{
      bytevalue = fgetc(fileptr);
      imagedata[index] = bytevalue;
      index ++; // im keeping the position now

   }while(index != 54);
}
////////////////

  fseek( fileptr, 10, SEEK_SET );
  int encrypt_pos = fgetc(fileptr) ;
  fseek(   fileptr, encrypt_pos, SEEK_SET ); // encryption position
  FILE *f2 = fopen("Mad_scientist_encrypted_cbc.bmp","w+b");
  fwrite(imagedata,1,sizeof(imagedata),f2);

  res = EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);  // context init - set cipher, key, init vector
  if(res != 1) exit(3);


// EVP_CIPHER_CTX_set_padding(ctx, 0);


  while (!feof(fileptr)) // expecting 1
  {
  ptLength = fread(pt, 1, sizeof(pt), fileptr);
  res = EVP_EncryptUpdate(ctx,  ct, &tmpLength, pt, ptLength);  // encryption of pt
if(res != 1) exit(4);
  ctLength += tmpLength;
  fwrite(ct,1,tmpLength,f2);

}
res = EVP_EncryptFinal_ex(ctx, ct , &tmpLength);  // get the remaining ct

if(res != 1)  exit(5);
ctLength += tmpLength;
  fwrite(ct,1,tmpLength,f2);




  printf ("Encrypted %d characters.\n", ctLength);

  /* Decryption */

  res = EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);  // context init for decryption
  if(res != 1) exit(3);

   fseek( f2, encrypt_pos, SEEK_SET );
  FILE *f3 = fopen("Mad_scientist_decrypted_cbc123.bmp","wb");
  fwrite(imagedata,1,sizeof(imagedata),f3);

  while (!feof(f2)) // expecting 1
  {
     ctLength=fread(ct, 1, sizeof(ct), f2);
  res = EVP_DecryptUpdate(ctx, pt, &tmpLength,  ct, ctLength);  // decrypt ct
  if(res != 1) exit(4);
  ptLength += tmpLength;
  fwrite(pt,1,tmpLength,f3);

}
res = EVP_DecryptFinal_ex(ctx, pt , &tmpLength);  // get the remaining plaintext
if(res != 1) exit(5);
ptLength += tmpLength;
fwrite(pt,1,tmpLength,f3);

  EVP_CIPHER_CTX_free(ctx);
  printf("CT: %s\nDT: %s\n", ct, pt);
  fclose(fileptr);
  fclose(f2);
  fclose(f3);
  exit(0);

 }
