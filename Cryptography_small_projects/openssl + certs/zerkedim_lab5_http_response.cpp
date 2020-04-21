#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include<fstream>

#define APIKEY "sadasdsadasd"
#define HOST "147.32.232.248"
#define PORT "443"

int main() {

    FILE* response = fopen("response.txt","w");
    BIO* bio;
    SSL* ssl;
    SSL_CTX* ctx;

    SSL_library_init();

    ctx = SSL_CTX_new(SSLv23_client_method());

    if (ctx == NULL)
    {
        printf("Ctx is null\n");
    }

    bio = BIO_new_ssl_connect(ctx);

    BIO_set_conn_hostname(bio, HOST ":" PORT);

    if(BIO_do_connect(bio) <= 0)
    {
        printf("Failed connection\n");
        return 1;
    }
    else
    {
        printf("Connected\n");
    }

    char* write_buf = "POST / HTTP/1.1\r\n"
                      "Host: " HOST "\r\n"
                      "Authorization: Basic " APIKEY "\r\n"
                      "Connection: close\r\n"
                      "\r\n";

  if(BIO_write(bio, write_buf, strlen(write_buf)) <= 0)
      {

                printf("Failed write\n");
        }


    int size;
    char buf[1024];

    for(;;)
    {

        size = BIO_read(bio, buf, 1023);

        if(size <= 0)
        {
            break;
        }

        //  Terminate the string with a 0, to let know C when the string ends

        buf[size] = 0;

      //  printf("%s", buf);
      fwrite(buf,1,sizeof(buf),response);
    }

    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    fclose(response);
    return 0;
}
