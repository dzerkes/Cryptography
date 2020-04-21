#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <stdbool.h>
//REF: https://codereview.stackexchange.com/questions/29198/random-string-generator-in-c
static char *rand_string(char *str, size_t size)
{
  const char charset[] = "Text for hash.";
  if (size) {
      --size;
      for (size_t n = 0; n < size; n++) {
          int key = rand() % (int) (sizeof charset - 1);
          str[n] = charset[key];
      }
      str[size] = '\0';
  }
  return str;
}

int main(int argc, char *argv[]){

  int i, res;
  char text[] = "Text for hash.";
  char hashFunction[] = "sha256";  // chosen hash function ("sha1", "md5" ...)
  EVP_MD_CTX *ctx;  // context structure
  const EVP_MD *type; // hash function type
  unsigned char hash[EVP_MAX_MD_SIZE]; // char array for hash - 64 bytes (max for sha 512)
  int length;  // resulting hash length

 
  

  /* Initialization of OpenSSL hash function list */
  OpenSSL_add_all_digests();
  /* Lookup of the needed hash function */
  type = EVP_get_digestbyname(hashFunction);

  /* If NULL returned, hash does not exist */
  if(!type) {
    printf("Hash %s does not exist.\n", hashFunction);
    exit(1);
  }
  ctx = EVP_MD_CTX_create(); // create context for hashing
  if(ctx == NULL) exit(2);

  /* Hash the text */
  do {

  rand_string(text, sizeof(text));
  printf("%s \n", text);
  res = EVP_DigestInit_ex(ctx, type, NULL); // context setup for our hash type
  if(res != 1) exit(3);
  res = EVP_DigestUpdate(ctx, text, strlen(text)); // feed the message in
  if(res != 1) exit(4);
  res = EVP_DigestFinal_ex(ctx, hash, (unsigned int *) &length); // get the hash
  if(res != 1) exit(5);
  // printf("%02x \n \n \n", hash[0]);		
 // printf("%02x \n \n \n", hash[1]);
 		
} while(!(hash[0] == 0xca && hash[1] == 0xfe));


  EVP_MD_CTX_destroy(ctx); // destroy the context

  /* Print the resulting hash */
  printf("Hash of the text \"%s\" is: ", text);
  for(i = 0; i < length; i++){
    printf("%02x", hash[i]);
  }
  printf("\n");

  exit(0);

}
