#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <errno.h>
#include <memory.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <fcntl.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netdb.h>

#include <linux/if_tun.h>
#include <getopt.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/rsa.h> 
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

#define PERROR(x) { perror(x); exit(1); }
#define ERROR(x, args ...) { fprintf(stderr,"ERROR:" x, ## args); exit(1); }


#define HMAC_LEN 16

#define BUFF_SIZE 51200
#define KEY_IV_SIZE 16

#define CHK_NULL(x) if ((x)==NULL) { printf("NULL!!\n"); exit(1); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }


static char SER_CERTF[] = "server.crt";
static char SER_KEYF[] = "server.key";
static char CACERT[] = "ca.crt";
static char SER_CERT_PASS[] = "password";

unsigned char KEY[KEY_IV_SIZE], IV[KEY_IV_SIZE];
int DEBUG = 1;
char *progname;

void my_err(char *msg, ...) {
	va_list argp;
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
}

void genKey(unsigned char* key) {
    int i;
    srand(time(NULL));
    for (i=0; i<KEY_IV_SIZE; i++)
        key[i] = 65 + (rand()%26);
}

void genIV(unsigned char* iv) {
    int i;
    srand(time(NULL));
    for (i=0; i<KEY_IV_SIZE; i++)
        iv[i] = 48 + (rand()%10);
}

void showKeyOrIV(unsigned char* chrs) {
    int i;
    for (i=0; i<KEY_IV_SIZE; i++)
        printf("%c", chrs[i]);
}

void getHash(char * msg, int len, char * digt) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    size_t md_len, i;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    char hashname[] = "md5";
    OpenSSL_add_all_digests();
    md = EVP_get_digestbyname(hashname);
    if(!md) {
        printf("Unknown message digest %s\n", hashname);
        exit(1);
    }
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, msg, len);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_destroy(mdctx);
    memcpy(digt, md_value, HMAC_LEN);
}

int checkHMAC(char * payload, int * l) {
    char digt1[HMAC_LEN], digt2[HMAC_LEN], buff[BUFF_SIZE];
    int i, len = *l;
    len -= HMAC_LEN;
    if (len <=0) return 1;
    memcpy(digt1, payload + len, HMAC_LEN);
    memcpy(buff, payload, len);
    getHash(buff, len, digt2);
    if (DEBUG) {
        printf("checking HMAC: ");
        for(i = 0; i < HMAC_LEN; i++) printf("%02x", digt1[i]);
        printf(" / ");
        for(i = 0; i < HMAC_LEN; i++) printf("%02x", digt2[i]);
        printf("\n");
    }
    *l = len;
    return strncmp(digt1, digt2, HMAC_LEN);
}

void appendHMAC(char * payload, int * l) {
    char digt[HMAC_LEN], buff[BUFF_SIZE];
    int i, len = *l;
    memcpy(buff, payload, len);
    getHash(buff, len, digt);
    for (i=0;i<HMAC_LEN;i++)
        *(payload + len + i) = digt[i];
    len += HMAC_LEN;
    if (DEBUG) {
        printf("\nappend HMAC: ");
        for(i = len-HMAC_LEN; i < len; i++) printf("%02x", *(payload+i));
        printf("\n");
    }
    *l = len;
}


void usage() {
    fprintf(stderr, "Usage: MiniVPN [-s port|-c targetip:port]\n");
    exit(0);
}

void sendKey(SSL* ssl, unsigned char* key) {
    int i;
    char buf[4096];
    buf[0] = 'k'; 
    for (i=0; i<KEY_IV_SIZE; i++)
        buf[i+1] = key[i];
    i = SSL_write(ssl, buf, KEY_IV_SIZE+1);
    CHK_SSL(i);
    // read echo
    i = SSL_read(ssl, buf, sizeof(buf) - 1);
    CHK_SSL(i);
    buf[i] = '\0';
    if (buf[0]=='l') {
        printf("Key confirmed by remote peer: ");
        showKeyOrIV(key);
        printf("\n");
    }
    else
        PERROR("Key exchange fail!\n");
}

void sendIV(SSL* ssl, unsigned char* iv) {
	int i;
	char buf[4096];
	buf[0] = 'i';
	for (i=0; i<KEY_IV_SIZE; i++)
		buf[i+1] = iv[i];
	i = SSL_write(ssl, buf, KEY_IV_SIZE+1);
	CHK_SSL(i);
	i = SSL_read(ssl, buf, sizeof(buf) - 1);
	CHK_SSL(i);
	buf[i] = '\0';
	if (buf[0]=='j') {
		printf("IV confirmed by remote peer: ");
		showKeyOrIV(iv);
		printf("\n");
	}
	else
		PERROR("IV exchange fail!\n");
}

int receiveKey(SSL* ssl, char* buf, size_t len, unsigned char* key) {
	int i;
	if (len!=KEY_IV_SIZE+1 || buf[0]!='k') return 0;
	for (i=1; i<len; i++)
		key[i-1] = buf[i];
	i = SSL_write(ssl, "l", 1);
	CHK_SSL(i);
	printf("KEY received: ");
	showKeyOrIV(key);
	printf("\n");
	return 1;
}

int receiveIV(SSL* ssl, char* buf, size_t len, unsigned char* iv) {
	int i;
	if (len!=KEY_IV_SIZE+1 || buf[0]!='i') return 0;
	for (i=1; i<len; i++)
		iv[i-1] = buf[i];
	i = SSL_write(ssl, "j", 1);
	CHK_SSL(i);
	printf("IV received: ");
	showKeyOrIV(iv);
	printf("\n");
	return 1;
}

void UDP(int listen_port, int pipefd) {
	struct sockaddr_in sin, sout;
	struct ifreq ifr;
	socklen_t soutlen;
	int fd, s, l, i, count = 0;
	int optval = 1;
	fd_set fdset;
	char buf[BUFF_SIZE], digt[HMAC_LEN];

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0) PERROR("open");

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN;
	strncpy(ifr.ifr_name, "tun%d", IFNAMSIZ);
	if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) PERROR("ioctl");
	printf("Allocated interface %s\n", ifr.ifr_name);

	s = socket(AF_INET, SOCK_DGRAM, 0);
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(listen_port);

	if (bind(s,(struct sockaddr *)&sin, sizeof(sin)) < 0) PERROR("bind");
	soutlen = sizeof(sout);

	if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
		perror("setsockopt()");
		exit(1);
	}
	while (1) {
		l = read(pipefd, buf, sizeof(buf));
		if (l > 0) {
			if (l == 1 && buf[0]=='q') {
				_exit(0);
			}
			else if (buf[0]=='k') {
				for (i=0; i<KEY_IV_SIZE; i++) {
					KEY[i] = buf[i+1];
					IV[i] = buf[i+KEY_IV_SIZE+1];
				}
				count++;
			}
			showKeyOrIV(KEY);
			printf("  IV: ");
			showKeyOrIV(IV);
			printf("\n");
		}
		if (!count) {
			sleep(1);
			continue;
		}

		FD_ZERO(&fdset);
		FD_SET(fd, &fdset);
		FD_SET(s, &fdset);
		if (select(fd+s+1, &fdset,NULL,NULL,NULL) < 0) PERROR("select");
		if (FD_ISSET(fd, &fdset)) {
			l = read(fd, buf, BUFF_SIZE);
			printf("Read %d bytes from the tap interface\n", l);
			if (l < 0) PERROR("read");

			unsigned char outbuf[BUFF_SIZE + EVP_MAX_BLOCK_LENGTH];
			int outlen, tmplen;


			if (DEBUG) {
				printf("\n(before crypted) payload: ");
				for(i = 0; i < l; i++) printf("%02x", *(buf+i));
				printf("\n");
			}

			EVP_CIPHER_CTX ctx;
			EVP_CIPHER_CTX_init(&ctx);
			EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, KEY, IV, 1);

			if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, buf, l)) {
				printf("error encrypt\n");
				EVP_CIPHER_CTX_cleanup(&ctx);
			}
			if(!EVP_CipherFinal_ex(&ctx, outbuf + outlen, &tmplen)) {
				printf("error encrypt\n");
				EVP_CIPHER_CTX_cleanup(&ctx);
			}
	
			
			if (DEBUG) {
				printf("\n(crypted) payload: ");
				for(i = 0; i < outlen; i++) printf("%02x", *(outbuf+i));
				printf("\n");
			}

			EVP_CIPHER_CTX_cleanup(&ctx);

			appendHMAC(buf, &l); 
			soutlen = sizeof(sout);
			if (sendto(s, buf, sizeof(buf), 0, (struct sockaddr *)&sout, soutlen) < 0) PERROR("sendto");
			printf("Written %d bytes to the network\n", l);
		}
		else {
			l = recvfrom(s, buf, BUFF_SIZE, 0, (struct sockaddr *)&sout, &soutlen);
			printf("Read %d bytes from the network\n", l);

			if (checkHMAC(buf, &l)) { 
   			 printf("HMAC mismatch.  Drop packet.\n");
			}
			unsigned char outbuf[BUFF_SIZE + EVP_MAX_BLOCK_LENGTH];
			int outlen, tmplen;


			EVP_CIPHER_CTX ctx;
			EVP_CIPHER_CTX_init(&ctx);
			EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, KEY, IV, 0);

			if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, buf, l)) {
				printf("error decrypt\n");
				EVP_CIPHER_CTX_cleanup(&ctx);
			}
			if(!EVP_CipherFinal_ex(&ctx, outbuf + outlen, &tmplen)) {
				printf("error decrypt\n");
				EVP_CIPHER_CTX_cleanup(&ctx);
			}
			if (DEBUG) {
				printf("\n(crypted) payload: ");
				for(i = 0; i < outlen; i++) printf("%02x", *(outbuf+i));
				printf("\n");
			}

			if (write(fd, buf, l) < 0) PERROR("write");
			printf("Written %d bytes to the tap interface\n", l);
		}
	}
}

int main(int argc, char *argv[]) {

	int tap_fd;
	char if_name[IFNAMSIZ] = "";
	int header_len = IP_HDR_LEN;
	socklen_t remotelen;
	int cliserv = -1;
	int fd[2];
	pid_t pid;
	int pipefd;
	int PORT = 55555;
	DEBUG = 1;

	pipe(fd);
	fcntl(fd[0], F_SETFL, O_NONBLOCK);

	if((pid = fork()) < 0) {
		perror("fork");
	}
	else if (pid > 0) {
		close(fd[0]);
		unsigned char* key = KEY;
		unsigned char* iv = IV;
		pipefd = fd[1];
		int err, listen_sd, sd, i;
		int _keyReady = 0, _ivReady = 0;
		struct sockaddr_in sa_serv, sa_cli;
		size_t client_len;
		SSL_CTX* ctx;
		SSL* ssl;
		char buf[4096];

		char* certf = SER_CERTF;
		char* keyf = SER_KEYF;
		SSL_METHOD* meth = SSLv23_server_method();
		char *pass = SER_CERT_PASS;
		SSL_load_error_strings();
		SSLeay_add_ssl_algorithms();
		ctx = SSL_CTX_new(meth);
		if (!ctx) {
			ERR_print_errors_fp(stderr);
			exit(2);
		}
		SSL_CTX_set_default_passwd_cb_userdata(ctx, pass);
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
		SSL_CTX_load_verify_locations(ctx, CACERT, NULL);
		if (SSL_CTX_use_certificate_file(ctx, certf, SSL_FILETYPE_PEM) <= 0) {
			ERR_print_errors_fp(stderr);
			exit(3);
		}
		if (SSL_CTX_use_PrivateKey_file(ctx, keyf, SSL_FILETYPE_PEM) <= 0) {
			ERR_print_errors_fp(stderr);
			exit(4);
		}
		if (!SSL_CTX_check_private_key(ctx)) {
			fprintf(stderr,"Private key does not match the certificate public key\n");
			exit(5);
		}
		listen_sd = socket(AF_INET, SOCK_STREAM, 0);
		CHK_ERR(listen_sd, "socket");

		memset(&sa_serv, '\0', sizeof(sa_serv));
		sa_serv.sin_family = AF_INET;
		sa_serv.sin_addr.s_addr = htonl(INADDR_ANY);
		sa_serv.sin_port = htons(PORT);

		err = bind(listen_sd, (struct sockaddr*) &sa_serv, sizeof (sa_serv));
		CHK_ERR(err, "bind");
		err = listen (listen_sd, 5);
		CHK_ERR(err, "listen");
		client_len = sizeof(sa_cli);
		sd = accept(listen_sd, (struct sockaddr*) &sa_cli, &client_len);
		CHK_ERR(sd, "accept");
		close(listen_sd);
		printf("Connection from %s:%i\n", inet_ntoa(sa_cli.sin_addr), ntohs(sa_cli.sin_port));


		ssl = SSL_new(ctx);
		CHK_NULL(ssl);
		SSL_set_fd(ssl, sd);
		err = SSL_accept(ssl);
		CHK_SSL(err);

		X509* peer_cert;
		char* str;
		char peer_CN[256];
		printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
		if (SSL_get_verify_result(ssl)!=X509_V_OK)
			PERROR("Certificate doesn't verify.\n");
		peer_cert = SSL_get_peer_certificate (ssl);
		if (peer_cert != NULL) {
			printf("OKAY\n");
		} else
			PERROR ("Peer does not have certificate.\n");

		while (1) {
			_keyReady = 0;
			_ivReady = 0;
			while (!_keyReady || !_ivReady) {
				err = SSL_read(ssl, buf, sizeof(buf) - 1);
				CHK_SSL(err);
				buf[err] = '\0';
				_keyReady = _keyReady || receiveKey(ssl, buf, err, KEY);
				_ivReady = _ivReady || receiveIV(ssl, buf, err, IV);
			}

			buf[0] = 'k';

			for (i=0; i<KEY_IV_SIZE; i++) {
				buf[i+1] = KEY[i];
				buf[i+KEY_IV_SIZE+1] = IV[i];
			}
			buf[KEY_IV_SIZE*2+1] = '\0';
			_keyReady = 0;
			_ivReady = 0;
			for (i=0; i<KEY_IV_SIZE; i++) {
				_keyReady = _keyReady || (int)KEY[i];
				_ivReady = _ivReady || (int)IV[i];
			}
			if (!_keyReady && !_ivReady) {
				printf("Disconnect signal from client received!\n");
				kill(pid, SIGTERM);
				wait();
				break;
			}
			write(pipefd, buf, KEY_IV_SIZE*2+2);
		}

		close(sd);
		SSL_free (ssl);
		SSL_CTX_free (ctx);
		printf("Parent process quit!\n");
	}
	else {
		close(fd[1]);
		UDP(PORT, fd[0]);
		printf("Child process quit!\n");
	}
}
