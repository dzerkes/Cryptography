#include <stdlib.h>
#include <openssl/evp.h>
#include <string.h>

int main(void) {

  unsigned char pt[1024] = "abcdefghijklmnopqrstuvwxyz0123";  // Known plaintext 1
  unsigned char ct[1024]  ;  // ciphertext 1
  unsigned char pt2[1024] = "This is my secret text, congratulations."; //Secret Plaintext 2
  unsigned char ct2[1024]; //ciphertext 2
  unsigned char key[EVP_MAX_KEY_LENGTH] = "SecretKey12345";  // encryption and decryption key
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
  res = EVP_EncryptUpdate(ctx,  ct2, &tmpLength, pt2, pt2Length);  // encryption of pt
  if(res != 1) exit(4);
  ct2Length += tmp2Length;
  res = EVP_EncryptFinal_ex(ctx, ct2 + ct2Length, &tmp2Length);  // get the remaining ct
  if(res != 1) exit(5);
  ct2Length += tmp2Length;

  printf ("Encrypted %d characters.\n", ct2Length);

  /* Decryption pt*/
  res = EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);  // context init for decryption
  if(res != 1) exit(3);
  res = EVP_DecryptUpdate(ctx, pt, &tmpLength,  ct, ctLength);  // decrypt ct
  if(res != 1) exit(4);
  ptLength += tmpLength;
  res = EVP_DecryptFinal_ex(ctx, pt + ptLength, &tmpLength);  // get the remaining plaintext
  if(res != 1) exit(5);
  ptLength += tmpLength;

  /* Decryption pt2*/
  res = EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);  // context init for decryption
  if(res != 1) exit(3);
  res = EVP_DecryptUpdate(ctx, pt2, &tmp2Length,  ct2, ct2Length);  // decrypt ct
  if(res != 1) exit(4);
  ptLength += tmp2Length;
  res = EVP_DecryptFinal_ex(ctx, pt2 + pt2Length, &tmp2Length);  // get the remaining plaintext
  if(res != 1) exit(5);
  ptLength += tmp2Length;


  /* Print out the encrypted and decrypted texts.
     Ciphertext will probably not be printable! */
  printf("CT1: %02x \n PT1: %s\n", ct, pt);
  printf("CT2: %02x \n PT2: %s\n", ct2, pt2);


//solution to task 2

    printf("so now lets say we dont know pt2 \n, we just wanted to encrypt it and try to see if we can find pt2  \n by only using pt1 key and pt2  \n so we have c1= p1 xor key AND c2 = p2 xor key and we know c2 key and c1 and p1 which is public  \n so by solving the equoation we can find key like:  \n key = c1 xor p1       ");	

	 char xor[1024]; // result of c2 xor c1 xor p1

 int i;

 for(i=0; i<1024; ++i)
        xor[i] = (char)(pt[i] ^ ct[i]);
        
	  /* Decryption pt2* with another way */
  res = EVP_DecryptInit_ex(ctx, cipher, NULL, xor, iv);  // context init for decryption
  if(res != 1) exit(3);
  res = EVP_DecryptUpdate(ctx, pt2, &tmp2Length,  ct2, ct2Length);  // decrypt ct
  if(res != 1) exit(4);
  ptLength += tmp2Length;
  res = EVP_DecryptFinal_ex(ctx, pt2 + pt2Length, &tmp2Length);  // get the remaining plaintext
  if(res != 1) exit(5);
  ptLength += tmp2Length;

  printf("CT2: %02x \n PT2: %s\n", ct2, pt2);	
	


   /* Clean up */
  EVP_CIPHER_CTX_free(ctx);


// 2nd try didnt work exactly because it prints hex numbers and i dont know how to get the real text we want

/*
  printf("so now lets say we dont know pt2 \n, we just wanted to encrypt it and try to see if we can find pt2  \n by only using pt1 key and pt2  \n so we have c1= p1 xor key AND c2 = p2 xor key and we know c2 key and c1 and p1 which is public  \n so by solving the equoation we can find p2 like:  \n p2 = c2 xor c1 xor p1       ");



 char xor[1024]; // result of c2 xor c1 xor p1

 int i;

 for(i=0; i<1024; ++i)
        xor[i] = (char)(ct2[i] ^ pt[i] ^ ct[i]);
        for(i=0; i<1024; ++i)
        printf("%02X ", xor[i]);
    printf("\n");

*/

  exit(0);
 }
