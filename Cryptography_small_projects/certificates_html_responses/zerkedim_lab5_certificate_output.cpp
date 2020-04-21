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
         servcert = SSL_get_peer_certificate(ssl);
         if (servcert!=NULL)
         {
           BIO * fileout = BIO_new_file("output.pem", "w"); // we use bio because we can use better filters for our purposes
           X509_print(fileout, servcert);
           PEM_write_bio_X509(fileout, servcert);
           BIO_free(fileout);
           X509_free (servcert);
          }

            SSL_free (ssl);
            }
            ::close(sd);

    }
    SSL_CTX_free (ctx);
    return 0;
}
