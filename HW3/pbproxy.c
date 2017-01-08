#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <openssl/aes.h>
#include <openssl/rand.h> 
#include <openssl/hmac.h>
#include <openssl/buffer.h>
extern char * optarg;
#define MAX_SIZE 1024*20


struct ctr_state {
    /* ivec[0..7] is the IV, ivec[8..15] is the big-endian counter */
    unsigned char ivec[16];  
    unsigned int num;
    unsigned char ecount[16];
};

void init_ctr(struct ctr_state *state, const unsigned char iv[8])
{
    /* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
     * first call. */
    state->num = 0;
    memset(state->ecount, 0, 16);

    /* Initialise counter in 'ivec' to 0 */
    memset(state->ivec + 8, 0, 8);

    /* Copy IV into 'ivec' */
    memcpy(state->ivec, iv, 8);
}

struct conn_t
{
    unsigned char iv[8];
    unsigned char key[256];
    int fd_proxys;
};

struct fd_t {
    int fd_proxyc;
    int fd_server;
};

struct server_t
{
    unsigned char iv[8];
    unsigned char key[256];
    struct fd_t fds;
};


static void * client_send(void * args)
{
    int n;
    int fd_proxys;
    AES_KEY aes_key;
    struct ctr_state cstate;
    unsigned char send_buff[MAX_SIZE];
    unsigned char msg_buff[MAX_SIZE];

    struct conn_t * pdata = (struct conn_t*)args;
    fd_proxys = pdata->fd_proxys;
    init_ctr(&cstate, pdata->iv);
    AES_set_encrypt_key(pdata->key, 128, &aes_key);

    while (1) {
        if ((n = read(0, send_buff, sizeof(send_buff) - 1)) <= 0) {
            perror("read ends......");
            break;
        }
        send_buff[n] = 0;
        //printf("have sent \"%s\" to remote server", send_buff);

        AES_ctr128_encrypt(send_buff, msg_buff, n,
                           &aes_key, cstate.ivec,
                           cstate.ecount, &cstate.num);
        //printf("Encryption from [%s] to [%s]\n", send_buff, msg_buff);

        if ((n = write(fd_proxys, msg_buff, n)) <= 0) {
            perror("write ends......");
            break;
        }
    }
    return NULL;
}

static void * client_recv(void * args)
{
    int n;
    int fd_proxys;
    AES_KEY aes_key;
    struct ctr_state cstate;
    unsigned char recv_buff[MAX_SIZE];
    unsigned char msg_buff[MAX_SIZE];

    struct conn_t * pdata = (struct conn_t*)args;
    fd_proxys = pdata->fd_proxys;
    init_ctr(&cstate, pdata->iv);
    AES_set_encrypt_key(pdata->key, 128, &aes_key);

    while (1) {
        if ((n = read(fd_proxys, recv_buff, sizeof(recv_buff) - 1)) <= 0) {
            break;
        }
        recv_buff[n] = 0;
        
        AES_ctr128_encrypt(recv_buff, msg_buff, n,
                           &aes_key, cstate.ivec,
                           cstate.ecount, &cstate.num);
        //printf("Decryption from [%s] to [%s]\n", recv_buff, msg_buff);

        write(1, msg_buff, n);
    }
    return NULL;
}

static int pbproxy_client(const char * mykey,
                              const char * ip, int port)
{
    int fd_proxys;
    struct sockaddr_in server;

    //Create socket
    fd_proxys = socket(AF_INET , SOCK_STREAM , 0);
    if (fd_proxys == -1) {
        perror("Could not create socket");
        return -1;
    }
    server.sin_addr.s_addr = inet_addr(ip);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    //Connect to remote proxy server
    if (connect(fd_proxys , (struct sockaddr *)&server , sizeof(server)) < 0) {
        perror("connect error %m");
        return -1;
    }

    struct conn_t * pdata =
            (struct conn_t *)malloc(sizeof(struct conn_t));
    if (pdata == NULL) {
        perror("malloc failed %m");
        return -1;
    }
    pdata->fd_proxys = fd_proxys;
    memcpy(pdata->key, mykey, sizeof(pdata->key));

    if (!RAND_bytes(pdata->iv, 8)) {
        perror("RAND_bytes error");
        free(pdata);
        return -1;
    }
    int n = 0;
    if ((n = write(fd_proxys, pdata->iv, 8)) < 0) {
        perror("send IV failed.");
        free(pdata);
        return -1;
    }

    pthread_t pid_send, pid_recv;
    int ret = pthread_create(&pid_send, NULL, client_send, (void*)pdata);
    if (ret != 0) {
        perror("pthread_create failed");
        free(pdata);
        return -1;
    }

    ret = pthread_create(&pid_recv, NULL,client_recv, (void*)pdata);
    if (ret != 0) {
        perror("pthread_create failed");
        free(pdata);
        return -1;
    }

    pthread_join(pid_send, NULL);
    pthread_join(pid_recv, NULL);
    free(pdata);
    return 0;
}



// Forward message proxy client => server
static void * handle_c2s(void * args)
{
    struct server_t * pdata = (struct server_t*)args;
    int fd_proxyc = ((struct server_t*)args)->fds.fd_proxyc;
    int fd_server = ((struct server_t*)args)->fds.fd_server;

    AES_KEY aes_key;
    struct ctr_state cstate;
    unsigned char recv_buff[MAX_SIZE];
    unsigned char msg_buff[MAX_SIZE];

    memset(recv_buff, '0', sizeof(recv_buff));
    init_ctr(&cstate, pdata->iv);
    AES_set_encrypt_key(pdata->key, 128, &aes_key);

    
    while (1) {
        int n = read(fd_proxyc, recv_buff, sizeof(recv_buff) - 1);
        if (n <= 0) {
            exit(1);
        }
        recv_buff[n] = 0;
        

        // Decrypt the message sent to the proxy client
        AES_ctr128_encrypt(recv_buff, msg_buff, n,
                           &aes_key, cstate.ivec,
                           cstate.ecount, &cstate.num);
        //printf("Decryption  [%s]\n",msg_buff);

        write(fd_server, msg_buff, n);
        //printf("c2s: The buffer is %s before decryption", recv_buff);

        memset(recv_buff, '0', sizeof(recv_buff));
    }
    close(fd_proxyc);
    close(fd_server);
    free(args);
    return NULL;
}


// Forward message server to proxy client
static void * handle_s2c(void * args)
{
    struct server_t * pdata = (struct server_t*)args;
    int fd_proxyc = ((struct server_t*)args)->fds.fd_proxyc;
    int fd_server = ((struct server_t*)args)->fds.fd_server;

    AES_KEY aes_key;
    struct ctr_state cstate;
    unsigned char recv_buff[MAX_SIZE];
    unsigned char msg_buff[MAX_SIZE];

    memset(recv_buff, '0', sizeof(recv_buff));
    init_ctr(&cstate, pdata->iv);
    AES_set_encrypt_key(pdata->key, 128, &aes_key);

    while (1) {
        int n = read(fd_server, recv_buff, sizeof(recv_buff) - 1);
        if (n <= 0) {
            
            break;
        }
        recv_buff[n] = 0;
        

        // Encrypt the message sent to the proxy client
        AES_ctr128_encrypt(recv_buff, msg_buff, n,
                           &aes_key, cstate.ivec,
                           cstate.ecount, &cstate.num);
        //printf("Encryption from [%s] to [%s]\n", recv_buff, msg_buff);

        write(fd_proxyc, msg_buff, n);
        //printf("s2c: the buffer is %s before encryption", recv_buff);

        memset(recv_buff, '0', sizeof(recv_buff));
    }
    close(fd_proxyc);
    close(fd_server);
    free(args);    
    return NULL;
}



static int pbproxy_server(const char * mykey,
                              const char * server_addr,
                              int server_port, int listen_port)
{
    
    //// Forward the traffic to the local server
    int fd_server;
    struct sockaddr_in server;

    int listenfd = 0, fd_proxyc = 0;
    struct sockaddr_in serv_addr;

    memset(&serv_addr, '0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(listen_port);
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    listen(listenfd, 10);

    while(1) {
        // Create connetions between proxyc---proxys
        fd_proxyc = accept(listenfd, (struct sockaddr*)NULL, NULL);
        if (fd_proxyc < 0) {
            perror("Error occured. accept() failed ");
            continue;
        }
        
        
        // Create connetions between proxys-----server
        fd_server = socket(AF_INET , SOCK_STREAM , 0);
        if (fd_server == -1) {
            perror("Could not create socket");
        }
        server.sin_addr.s_addr = inet_addr(server_addr);
        server.sin_family = AF_INET;
        server.sin_port = htons(server_port);
        if (connect(fd_server , (struct sockaddr *)&server , sizeof(server)) < 0) {
            perror("Connect port error");
            close(fd_proxyc);
            continue;
        }
        
        

        struct server_t * pdata =
                (struct server_t *)malloc(sizeof(struct server_t));

        
        pdata->fds.fd_proxyc = fd_proxyc;
        pdata->fds.fd_server = fd_server;        
        memcpy(pdata->key, mykey, sizeof(pdata->key));
        
        // Get different IVs for each session
        int n;
        if ((n = read(fd_proxyc, pdata->iv, 8)) <= 0) {
           perror("read IV failed");
            continue;
        }
        for (n = 0; n<8; ++n) {
            
        }

        // Duplicate another thread data
        struct server_t * pdata2 =
                (struct server_t *)malloc(sizeof(struct server_t));
        memcpy(pdata2, pdata, sizeof(struct server_t));

        // Create 2 threads for each session
        pthread_t pid_c2s, pid_s2c;
        // c2s: proxy client => proxy server
        int ret = pthread_create(&pid_c2s, NULL, handle_c2s, (void*)pdata);
        if (ret != 0) {
            perror("pthread_create failed");
            return -1;
        }
        // s2c: proxy server => proxy client
        ret = pthread_create(&pid_s2c, NULL, handle_s2c, (void*)pdata2);
        if (ret != 0) {
            perror("pthread_create failed");
            return -1;
        }

    }
    return 0;
}

int main(int argc, char *argv[])
{  
int op ,listening_port,proxy_portno;
int server_mode=0;
const char *mykey,* proxy_address;
    
    
    if (argc < 5) {
        printf ("Invalid argument!");
        return -1;            
    }
    
    
    while ((op = getopt(argc, argv, "l:k:")) != -1) {
        switch (op) {
        case 'l':
            listening_port = atoi(optarg);
            server_mode =1;
            break;
        case 'k':
            mykey=optarg;  
            break;
        default:
            printf("Invalid argument!");
            return -1;            
        }

    }
    
if (mykey == NULL) {
		fprintf(stderr, "Key file not specified!\n");
		return 0;
	}
if (optind == argc - 2) {
    proxy_address = argv[optind];
    proxy_portno = atoi(argv[optind+1]);
}
else {
	fprintf(stderr, "optind: %d, argc: %d\n", optind, argc);
	fprintf(stderr, "Incorrect destination and port arguments. Exiting...\n");
		return 0;
	}
if (server_mode) {//if the listening port is provided it becomes server process
        pbproxy_server(mykey, proxy_address, proxy_portno, listening_port);
    } 
else {//no listening port client process
        pbproxy_client(mykey, proxy_address, proxy_portno);
    }

    return 0;
}


