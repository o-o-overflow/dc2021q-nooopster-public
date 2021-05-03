#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <stdarg.h>
#include <pthread.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>

#include "codes.h"

// #define DEBUG 1

#ifdef DEBUG
#define DBG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DBG(...) do {} while (0)
#endif

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

// FIXME: Handle MD5 (doesn't appear necessary)
// FIXME: Handle MP3 info detection (doesn't appear necessary)

// main page: http://www.napster.com/client/home.html
// discover page: http://www.napster.com
// help page: http://faq.napster.com

static const char *TRACKER_HOST = "127.0.0.1";
#define TRACKER_PORT 8888

#define DATA_PORT 7070
#define SHARED_PATH "shared"

#define LISTING_PATH_PREFIX "\\shared\\"

#define USERNAME "nooopster"
#define PASSWORD "password"
#define CLIENT_INFO "nooopster-v0.0.0"

#pragma pack(push)
#pragma pack(1)
struct nap_msg_header_t {
	/* Note: fields are little endian on the wire */
	uint16_t mlen;
	uint16_t mtype;
};
#pragma pack(pop)

struct nap_server_conn_t {
	struct sockaddr_in sa;
	int sock;

	// Last received message
	int msg_len;
	int msg_type;
	char *msg_buf;
};

struct known_peer {
	char *name;
	struct known_peer *next;
} *known_peers;

pthread_mutex_t known_peer_lock = PTHREAD_MUTEX_INITIALIZER;

bool is_peer_known(const char *name)
{
	bool result = false;
	pthread_mutex_lock(&known_peer_lock);

	for (struct known_peer *peer = known_peers;
		 peer != NULL;
		 peer = peer->next) {
		if (!strcmp(name, peer->name)) {
			result = true;
			break;
		}
	}

	pthread_mutex_unlock(&known_peer_lock);
	return result;
}

void add_known_peer(const char *name)
{
	if (is_peer_known(name)) {
		return;
	}

	pthread_mutex_lock(&known_peer_lock);
	struct known_peer *p = malloc(sizeof(struct known_peer));
	p->name = strdup(name);
	p->next = known_peers;
	known_peers = p;
	pthread_mutex_unlock(&known_peer_lock);
}

void nap_connect(struct nap_server_conn_t *n)
{
	DBG("connecting to %s:%d\n", TRACKER_HOST, TRACKER_PORT);

	n->sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (n->sock == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset(&n->sa, 0, sizeof(n->sa));
	n->sa.sin_family = AF_INET;
	n->sa.sin_port = htons(TRACKER_PORT);
	if (inet_pton(AF_INET, TRACKER_HOST, &n->sa.sin_addr) != 1) {
		perror("inet_pton");
		exit(EXIT_FAILURE);
	}

	if (connect(n->sock, (struct sockaddr *)&n->sa, sizeof(n->sa)) == -1) {
		perror("connect");
		exit(EXIT_FAILURE);
	}

	DBG("connected\n");
}

void nap_disconnect(struct nap_server_conn_t *n)
{
	close(n->sock);
}

void nap_send_msg(struct nap_server_conn_t *n, int mtype, const char *msg, ...)
{
	struct nap_msg_header_t hdr;

	char buf[256];
	va_list args;
	va_start(args, msg);
	vsnprintf(buf, sizeof(buf), msg, args);
	va_end(args);

	hdr.mlen = strlen(buf);
	hdr.mtype = (uint16_t)mtype;

	DBG("[send] %d%s%s\n", mtype, hdr.mlen > 0 ? ": " : "", buf);

	ssize_t res = send(n->sock, &hdr, sizeof(hdr), 0);
	if (res != sizeof(hdr)) {
		DBG("failed to send msg header");
		exit(EXIT_FAILURE);
	}

	res = send(n->sock, buf, hdr.mlen, 0);
	if (res != hdr.mlen) {
		DBG("failed to send msg data");
		exit(EXIT_FAILURE);
	}
}

int nap_recv_msg(struct nap_server_conn_t *n)
{
	if (n->msg_buf) {
		free(n->msg_buf);
		n->msg_type = 0;
		n->msg_len = 0;
		n->msg_buf = NULL;
	}

	struct nap_msg_header_t hdr;
	ssize_t res = recv(n->sock, &hdr, sizeof(hdr), 0);
	if (res != sizeof(hdr)) {
		DBG("failed to recv msg header");
		exit(EXIT_FAILURE);
	}

	n->msg_type = hdr.mtype;
	n->msg_len = hdr.mlen;

	if (hdr.mlen == 0) {
		DBG("[recv] %d|\n", n->msg_type);
		return n->msg_type;
	}

	char *buf = malloc(hdr.mlen + 1);
	assert(buf != NULL);

	res = recv(n->sock, buf, hdr.mlen, 0);
	if (res != hdr.mlen) {
		DBG("failed to recv msg data");
		exit(EXIT_FAILURE);
	}

	buf[hdr.mlen] = 0;
	n->msg_buf = buf;

	DBG("[recv] %d: %s|\n", n->msg_type, n->msg_buf);
	return n->msg_type;
}

int count_msg_fields(char *s)
{
	int num_fields = 0;

	for (char *p = s; *p; ) {
		num_fields++;

		// Handle quoted fields, which may contain spaces
		if (*p == '"') {
			// Note: Protocol apparently lacks proper support for escaping quote
			// characters. Simply scan forward for the terminating quote char.
			p = strchr(p+1, '"');
			if (p == NULL) {
				// Did not find ending quote!
				break;
			}
		}

		// Seek to next space
		p = strchr(p, ' ');
		if (p) {
			p++;
		} else {
			// Assume end of message.
			break;
		}
	}

	return num_fields;
}

// A rudimentary message tokenizer that assumes:
//   - Fields are separated by space characters
//   - Fields that begin with double quote character (") may contain spaces, but no quotes (and there's no quote escape char)
//   - Fields do not contain 00 bytes. There is only one, and it is at the end of the buffer.
//
// Converts the delimiting space characters to null bytes and returns number
// of fields found. Use `get_msg_field_*` to get respective field.
int tokenize_msg(char *s)
{
	int num_fields = 0;

	for (char *p = s; *p; ) {
		num_fields++;

		// Handle quoted fields, which may contain spaces
		if (*p == '"') {
			// Note: Protocol apparently lacks proper support for escaping quote
			// characters. Simply scan forward for the terminating quote char.
			*p++ = '\x00';
			p = strchr(p, '"');
			if (p == NULL) {
				// Did not find ending quote!
				break;
			}
			*p++ = '\x00';
		}

		// Seek to next space
		p = strchr(p, ' ');
		if (p) {
			// Found separating space char
			*p = '\x00';
			p++;
		} else {
			// Assume end of message.
			break;
		}
	}

	return num_fields;
}

// Note: Assumes `field` is valid and never exceeds maximum number
// of fields
char *get_msg_field_str(char *s, int field)
{
	char *p = s;
	for (int i = 0; i < field; i++) {
		// Skip over this token by seeking to null byte
		while (*p) {
			p++;
		}

		// Now seek past any run of null bytes
		while (!(*p)) {
			p++;
		}
	}

	return p;
}

int get_msg_field_int(char *s, int field)
{
	return atoi(get_msg_field_str(s, field));
}

struct peer_connection {
	pthread_t thread;
	int sock;
	struct sockaddr_in addr;
};

void *handle_peer_connection(void *opaque)
{
	struct peer_connection *peer = opaque;
	int f = -1;

	// Client-Client protocol note: there is no message type / length header
	// like there is with the Client-Server protocol, nor is there a unique
	// message termination sequence.

	// Sender first sends ASCII '1' char
	if (send(peer->sock, "1", 1, 0) != 1) {
		DBG("send");
		goto shutdown;
	}

	// Receive command word. The only supported command is 'GET', some clients
	// support remote file browsing via 'GETLIST'.
	char buf[256];

	for (int p = 0; p < 3;) { // Assumption: All message commands are 3 bytes (only GET supported)
		ssize_t res = recv(peer->sock, &buf[p], 3, 0);
		if (res < 0) {
			DBG("recv");
			goto shutdown;
		} else if (res == 0) {
			goto shutdown;
		}

		p += res;
	}

	// FIXME: If adding additional command support, handle case where reading
	// command also pulls in field bytes which should be accounted for below.

	if (memcmp(buf, "GET", 3) == 0) {
		// Receive command arguments. Unfortunately the protocol lacks the
		// length of the message here. We will stop reading args simply once
		// we have the required 3 fields.
		//
		// If for some reason the message came in very slowly, the final
		// parameter might not be fully consumed. Expect that this will
		// usually arrive in one shot.
		buf[0] = 0;
		for (int p = 0; p < sizeof(buf)-1; ) {
			ssize_t res = recv(peer->sock, &buf[p], sizeof(buf)-1-p, 0);
			if (res < 0) {
				DBG("recv");
				goto shutdown;
			} else if (res == 0) {
				goto shutdown;
			}

			p += res;
			buf[p] = 0;

			if (count_msg_fields(buf) >= 3) {
				break;
			}
		}

		int num_args = tokenize_msg(buf);
		if (num_args != 3) {
			goto invalid_request;
		}

		//
		// VULNERABILITY: Arbitrary file read. Other clients discover files
		// based on a listing of the shared directory, but because we do not
		// crosscheck against the server's message, and due to bad path
		// sanitization here, we allow any arbitrary file read with a properly
		// formatted message.
		//

		const char *peername = get_msg_field_str(buf, 0);
		if (!is_peer_known(peername)) {
			goto invalid_request;
		}

		const char *filename = get_msg_field_str(buf, 1);

		// Skip filename prefix
		if (memcmp(filename, LISTING_PATH_PREFIX, strlen(LISTING_PATH_PREFIX)) != 0) {
			goto invalid_request;
		}
		filename += strlen(LISTING_PATH_PREFIX);
		int offset = get_msg_field_int(buf, 2);
		DBG("peer '%s' requested upload of '%s' at offset %d\n", peername, filename, offset);

		struct stat st;
		stat(filename, &st);
		if (!S_ISREG(st.st_mode)) {
			DBG("skipping non-file: %s\n", filename);
			goto invalid_request;
		}

		f = open(filename, O_RDONLY);
		if (f < 0) {
			DBG("failed to open: %s\n", filename);
			goto invalid_request;
		}

		// Send file size
		char fsize_buf[32];
		snprintf(fsize_buf, sizeof(fsize_buf), "%ld", st.st_size);
		ssize_t res = send(peer->sock, fsize_buf, strlen(fsize_buf), 0);
		if (res != strlen(fsize_buf)) {
			goto transfer_done;
		}

		int bytes_to_send = st.st_size;
		int bytes_sent = 0;
		while (bytes_sent < bytes_to_send) {
			int chunk_bytes_sent = sendfile(peer->sock, f, NULL, st.st_size);
			if (chunk_bytes_sent < 0) {
				DBG("sendfile");
				goto transfer_done;
			}
			bytes_sent += chunk_bytes_sent;
		}

		DBG("transfer complete!\n");
	} else {
		// Unknown command
		goto invalid_request;
	}

transfer_done:
	close(f);
	goto shutdown;

invalid_request:
	DBG("request invalid!\n");
	const char *msg = "INVALID REQUEST";
	if (send(peer->sock, msg, strlen(msg), 0) != strlen(msg)) {
		DBG("send");
	}

shutdown:
	close(peer->sock);
	free(peer);
	DBG("done\n");
	return NULL;
}

void *data_server_main(void *opaque)
{
	int sock;

	DBG("starting data server...\n");

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	int enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(DATA_PORT);

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	if (listen(sock, SOMAXCONN) != 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	DBG("listening on port %d for data connections...\n", DATA_PORT);
	struct sockaddr_in remote;
	socklen_t len;
	while (1) {
		int connfd = accept(sock, (struct sockaddr *)&remote, &len);
		if (connfd < 0) {
			perror("accept");
			exit(EXIT_FAILURE);
		}

		char remote_str[32];
		if (inet_ntop(AF_INET, &remote.sin_addr, remote_str, sizeof(remote_str)) == NULL) {
			perror("inet_ntop");
			continue;
		}

		DBG("new connection from %s:%d\n", remote_str, ntohs(remote.sin_port));

		struct peer_connection *peer = malloc(sizeof(struct peer_connection));
		if (peer == NULL) {
			// OOM
			close(connfd);
			continue;
		}
		peer->sock = connfd;
		peer->addr = remote;
		if (pthread_create(&peer->thread, NULL, handle_peer_connection, peer) != 0) {
			perror("pthread_create");
			close(connfd);
			continue;
		}
	}
}

int main(int argc, char const *argv[])
{
	pthread_t data_server_thread;

	struct {
	char msg[128];
	char msg_file[32];
	} announcement = {0};

	if (argc > 1) {
		TRACKER_HOST = argv[1];
	}

	signal(SIGPIPE, SIG_IGN);

	if (chdir(SHARED_PATH) != 0) {
		fprintf(stderr, "error: cannot navigate to shared path: %s\n", SHARED_PATH);
		perror("chdir");
		exit(EXIT_FAILURE);
	}

	struct nap_server_conn_t n;
	memset(&n, 0, sizeof(n));
	nap_connect(&n);

	// Attempt login without registering
	nap_send_msg(&n, NAP_MKUSER, USERNAME);
	if (nap_recv_msg(&n) != NAP_UNOK) {
		DBG("username not ok\n");
		exit(EXIT_FAILURE);
	}

	nap_send_msg(&n, NAP_LOGIN, "%s %s %d \"%s\" 0", USERNAME, PASSWORD, DATA_PORT, CLIENT_INFO);
	if (nap_recv_msg(&n) != NAP_LOGSUCCESS) {
		DBG("failed login\n");
		exit(EXIT_FAILURE);
	}

	DBG("login ok\n");

	// Fire up data serving thread
	if (pthread_create(&data_server_thread, NULL, &data_server_main, NULL) != 0) {
		DBG("pthread_create\n");
		exit(EXIT_FAILURE);
	}

	// Share files in the SHARED_PATH directory
	DIR *dir;
	struct dirent *entry;
	if ((dir = opendir(".")) == NULL) {
		perror("opendir\n");
		exit(EXIT_FAILURE);
	}

	int count = 0;
	while ((entry = readdir(dir)) != NULL) {
		// Check to see if this is a file or not
		struct stat st;
		stat(entry->d_name, &st);
		if (!S_ISREG(st.st_mode)) {
			DBG("skipping non-file: %s\n", entry->d_name);
			continue;
		}

		if (access(entry->d_name, R_OK) != 0) {
			DBG("skipping non-readable file: %s\n", entry->d_name);
			continue;
		}

		const char *md5 = "b92870e0d41bc8e698cf2f0a1ddfeac7-100";
		int size = st.st_size;
		int bitrate = 24; // Dummy
		int freq = 16000; // Dummy
		int time = 600; // Dummy

		DBG("sharing file: %s\n", entry->d_name);
		// XXX: Adding path prefix to filename. Apparently this is required
		// to get the file to show up in search results from opennap? Why?
		nap_send_msg(&n, NAP_SFILE, "\"%s%s\" %s %d %d %d %d",
			LISTING_PATH_PREFIX, entry->d_name, md5, size, bitrate, freq, time);
		count++;
	}

	DBG("sharing %d files\n", count);

	closedir(dir);

	struct pollfd fds[1];
	fds[0].fd = n.sock;
	fds[0].events = POLLIN;

	const char *room = "chat";
	nap_send_msg(&n, 0x190, room);

    const char *quotes[] = {
            "hey there! check out my files",
            "have you seen my cool stuff?",
            "am I on your hotlist?",
            "what are you waiting for...",
    };
    int annoy_counter = 0;

	while (1) {
		int rc = poll(fds, 1, 10*1000);
		if (rc < 0) {
			DBG("poll");
			break;
		} else if (rc == 0) {
			// Timeout occured

			// A contrived thing to announce some messages for
			//    - Players to see client presence
			//    - Players to leak the flag if they can set an announcement file
			const char *msg = NULL;
			if (strlen(announcement.msg) > 0) {
				// Pending announcement message
				msg = announcement.msg;
			} else if (strlen(announcement.msg_file) > 0) {
				// Pending announcement from file
				FILE *fd = fopen(announcement.msg_file, "r");
				if (fd != NULL) {
					fgets(announcement.msg, sizeof(announcement.msg), fd);
					size_t len = strlen(announcement.msg);
					if (len > 0) {
						if (announcement.msg[len-1] == '\n') {
							announcement.msg[len-1] = '\x00';
						}
					}
					fclose(fd);

					msg = announcement.msg;
					announcement.msg_file[0] = 0;
				}
			} else {
				// Just say a random thing
				msg = quotes[annoy_counter++ % ARRAY_SIZE(quotes)];
			}

			if (msg != NULL) {
				nap_send_msg(&n, NAP_SAY, "#%s %s", room, msg);
			}

			announcement.msg[0] = 0;

			continue;
		}

		// A message is pending
		int msg = nap_recv_msg(&n);

		switch (msg) {
		case NAP_FREQ: {
			DBG("upload requested!\n");
			int num_fields = tokenize_msg(n.msg_buf);
			if (num_fields != 2) {
				DBG("invalid request\n");
				break;
			}

			const char *peername = get_msg_field_str(n.msg_buf, 0);
			add_known_peer(peername);

			const char *filename = get_msg_field_str(n.msg_buf, 1);
			DBG("peer '%s' requested upload of %s\n", peername, filename);

			// Accept
			DBG("accepted!\n");
			nap_send_msg(&n, NAP_GFR, "%s \"%s\"", peername, filename);
			break;
			}
		}
	}

	nap_disconnect(&n);
	return 0;
}
