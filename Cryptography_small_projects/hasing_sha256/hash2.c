#include <stdlib.h>
#include <openssl/evp.h>
#include <string.h>

int main(void) {
  unsigned char xor_pt2[1024];
  unsigned char pt[1024] = "abcdefghijklmnopqrstuvwxyz0123";  // Known plaintext 1
  unsigned char ct[1024]  ;  // ciphertext 1
  unsigned char pt2[1024] ="ThisIsMySecretTextCongrats0123"; //Secret Plaintext 2
  unsigned char ct2[1024]; //ciphertext 2
  unsigned char key[EVP_MAX_KEY_LENGTH] = "1234567890asdfgh";  // encryption and decryption key
  unsigned char iv[EVP_MAX_IV_LENGTH] = "initial vector";  // initialization vector
  const char cipherName[] = "RC4";
  const EVP_CIPHER * cipher;

  int ptLength = strlen((const char*) pt);
  int pt2Length = strlen((const char*) pt2);
  int ctLength = 0;
  int ct2Length = 0;
  int tmpLength = 0;
  int tmp2Length = 0;
  int res;

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

  printf("pt: %s\n", pt);
  printf("pt2: %s\n", pt2);

  // init encrypt
  res = EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);  // context init - set cipher, key, init vector
  if(res != 1) exit(3);
  /* Encryption pt*/
  res = EVP_EncryptUpdate(ctx,  ct, &tmpLength, pt, ptLength);  // encryption of pt
  if(res != 1) exit(4);
  ctLength += tmpLength;
  res = EVP_EncryptFinal_ex(ctx, ct + ctLength, &tmpLength);  // get the remaining ct
  if(res != 1) exit(5);
  ctLength += tmpLength;

  printf ("Encrypted %d characters.\n", ctLength);

  /* Encryption pt2*/
  res = EVP_EncryptUpdate(ctx,  ct2, &tmp2Length, pt2, pt2Length);  // encryption of pt
  if(res != 1) exit(4);
  ct2Length += tmp2Length;
  res = EVP_EncryptFinal_ex(ctx, ct2 + ct2Length, &tmp2Length);  // get the remaining ct
  if(res != 1) exit(5);
  ct2Length += tmp2Length;

  printf ("Encrypted %d characters.\n", ct2Length);

 // initialization of decryption
  res = EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);  // context init for decryption
  if(res != 1) exit(3);

    /* Decryption pt*/

  res = EVP_DecryptUpdate(ctx, pt, &tmpLength,  ct, ctLength);  // decrypt ct
  if(res != 1) exit(4);
  ptLength += tmpLength;
  res = EVP_DecryptFinal_ex(ctx, pt + ptLength, &tmpLength);  // get the remaining plaintext
  if(res != 1) exit(5);
  ptLength += tmpLength;

  /* Decryption pt2*/

  res = EVP_DecryptUpdate(ctx, pt2, &tmp2Length,  ct2, ct2Length);  // decrypt ct
  if(res != 1) exit(4);
  pt2Length += tmp2Length;
  res = EVP_DecryptFinal_ex(ctx, pt2 + pt2Length, &tmp2Length);  // get the remaining plaintext
  if(res != 1) exit(5);
  pt2Length += tmp2Length;


  /* Print out the encrypted and decrypted texts.
     Ciphertext will probably not be printable if i print it as string so i print it with 02x type*/
  printf("CT1: %02x \nPT1: %02x\n", ct, pt);
  printf("CT2: %02x \nPT2: %02x\n", ct2, pt2);

//solution to task 2
printf("to find pt2 we need to do pt2 = ct2 xor pt1 xor ct2  ");

xor_pt2 = ct ^ pt ^ ct2 ;


/*
for(int i=0; i<1024 ; ++i)
  printf("i = %d -----xorpt2: %02x ------ pt2: %02x ------ ct2:%02x ---------- ct:%02x------------pt:%02x \n",i,xor_pt2[i],pt2[i],ct2[i],ct[i],pt[i]);
*/
if(xor_pt2 == pt2)
  printf(" \n \n Decryption Worked -> PT2: %02x ", xor_pt2);

  EVP_CIPHER_CTX_free(ctx);



 exit(0);


 }
