#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

int main()
{
    SSLeay_add_ssl_algorithms();  SSL_load_error_strings();SSL_CTX* ctx = SSL_CTX_new (SSLv23_method());
    struct sockaddr_in sa;
    X509*    servcert;
    SSL*     ssl;
   //init socket
    int sd = ::socket (AF_INET, SOCK_STREAM, 0);
    if (sd!=-1 && ctx!=NULL) // if all ok go on
    {
        memset (&sa, '\0', sizeof(sa));
        sa.sin_family = AF_INET; // ipv4 address family
        sa.sin_addr.s_addr = inet_addr ("147.32.232.248");//ip of server -> i took the name of site and resolved it online to this ip
        sa.sin_port = htons(443);  // port number

         ::connect(sd, (struct sockaddr*) &sa, sizeof(sa)); // connect to the server
          ssl = SSL_new (ctx);
          if (ssl!=NULL)
          {
          SSL_set_fd(ssl, sd);

          SSL_connect(ssl);
          //1st task
          const SSL_CIPHER *cipher;
          cipher = SSL_get_current_cipher(ssl);
          printf("Cipher name: %s ", SSL_CIPHER_get_name(cipher) ? SSL_CIPHER_get_name(cipher) : "no cipher");
          printf("So we have an ECDHE-RSA which is an elliptic curve diffie-hellman key exchange signed with RSA and then aes256 with gsm and  hash sha384");
          SSL_free (ssl);
          printf("\n \n now lets try to disable cryptosuite before connect");
        }
          SSL*     ssl2;
          ssl2 = SSL_new (ctx);
          SSL_CTX_set_default_verify_paths(ctx);
          if (ssl2!=NULL)
          {
          SSL_set_fd(ssl2, sd);
          SSL_set_cipher_list(ssl2, "ALL:!ECDHE-RSA-AES256-GCM-SHA384");
          const SSL_CIPHER *cipher2;
          cipher2 = SSL_get_current_cipher(ssl2);
          printf("Cipher name: %s \n \n", SSL_CIPHER_get_name(cipher2) ? SSL_CIPHER_get_name(cipher2) : "no cipher");
          SSL_connect(ssl2);
          long res = SSL_get_verify_result(ssl2);
          if(!(X509_V_OK == res)){
            printf(" \n \n problem in verification \n \n");
          }else{
            printf(" \n \n verification is ok \n \n ");
          }
          printf("Print out all the ciphers that are available in your client \n ");
          int index = 0;
          const char *next = NULL;
          do {
            next = SSL_get_cipher_list(ssl2,index);
            if (next != NULL) {
              printf("  %s \n ",next);
              index++;
            }
          }
          while (next != NULL);

        }


            SSL_free(ssl2);
            }
            ::close(sd);


    SSL_CTX_free (ctx);
    return 0;
}
