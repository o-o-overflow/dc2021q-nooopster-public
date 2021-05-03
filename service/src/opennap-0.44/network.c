/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id: network.c,v 1.46 2001/09/22 06:04:26 drscholl Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#if !defined(WIN32) || defined(__CYGWIN__)
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/resource.h>
#endif /* !WIN32 */
#include "opennap.h"
#include "debug.h"

/* solaris 2.6 doesn't seem to define this */
#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

unsigned int
lookup_ip (const char *host)
{
    struct hostent *he;
    unsigned int ip;

    log_message ("lookup_ip: resolving %s", host);
    /* check for dot-quad notation.  Win95's gethostbyname() doesn't seem
       to return the ip address properly for this case like every other OS */
    ip = inet_addr (host);
    if (ip == INADDR_NONE)
    {
	he = gethostbyname (host);
	if (!he)
	{
	    log_message ("lookup_ip: can't find ip for host %s", host);
	    return 0;
	}
	memcpy (&ip, he->h_addr_list[0], he->h_length);
    }
    log_message ("lookup_ip: %s is %s", host, my_ntoa (ip));
    return ip;
}

int
set_nonblocking (int f)
{
    /* set the socket to be nonblocking */
#if !defined(WIN32) || defined(__CYGWIN__)
    if (fcntl (f, F_SETFL, O_NONBLOCK) != 0)
#else
    int     val = 1;

    if (ioctlsocket (f, FIONBIO, &val) != 0)
#endif /* !WIN32 */
    {
	log_message ("set_nonblocking: fcntl: %s", strerror (errno));
	return -1;
    }
    return 0;
}

int
set_tcp_buffer_len (int f, int bytes)
{
    if (setsockopt
	(f, SOL_SOCKET, SO_SNDBUF, SOCKOPTCAST & bytes, sizeof (bytes)) == -1)
    {
	log_message ("set_tcp_buffer_len: setsockopt: %s (errno %d)",
	     strerror (errno), errno);
	return -1;
    }
    if (setsockopt
	(f, SOL_SOCKET, SO_RCVBUF, SOCKOPTCAST & bytes, sizeof (bytes)) == -1)
    {
	log_message ("set_tcp_buffer_len: setsockopt: %s (errno %d)",
	     strerror (errno), errno);
	return -1;
    }
    return 0;
}

int
new_tcp_socket (int options)
{
    int     f;

    f = socket (AF_INET, SOCK_STREAM, 0);
    if (f < 0)
    {
	logerr ("new_tcp_socket", "socket");
	return -1;
    }
    if (options & ON_NONBLOCKING)
    {
	if (set_nonblocking (f))
	{
	    CLOSE (f);
	    return -1;
	}
    }
    if (options & ON_REUSEADDR)
    {
	int     i = 1;

	if (setsockopt
	    (f, SOL_SOCKET, SO_REUSEADDR, SOCKOPTCAST & i, sizeof (i)) != 0)
	{
	    CLOSE (f);
	    nlogerr ("new_tcp_socket", "setsockopt");
	    exit (1);
	}
    }
    return f;
}

int
set_keepalive (int f, int on)
{
    if (setsockopt
	(f, SOL_SOCKET, SO_KEEPALIVE, SOCKOPTCAST & on, sizeof (on)) == -1)
    {
	log_message ("set_keepalive: setsockopt: %s (errno %d).",
	     strerror (errno), errno);
	return -1;
    }
    return 0;
}

int
bind_interface (int fd, unsigned int ip, int port)
{
    struct sockaddr_in sin;

    memset (&sin, 0, sizeof (sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip;
    sin.sin_port = htons (port);
    if (bind (fd, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
	nlogerr ("bind_interface", "bind");
	return -1;
    }
    return 0;
}

int
make_tcp_connection (const char *host, int port, unsigned int *ip)
{
    struct sockaddr_in sin;
    int     f;

    memset (&sin, 0, sizeof (sin));
    sin.sin_port = htons (port);
    sin.sin_family = AF_INET;
    if ((sin.sin_addr.s_addr = lookup_ip (host)) == 0)
	return -1;
    if (ip)
	*ip = sin.sin_addr.s_addr;
    if ((f = new_tcp_socket (ON_NONBLOCKING)) == -1)
	return -1;

    /* if an interface was specify, bind to it before connecting */
    if (Interface)
	bind_interface (f, Interface, 0);

    /* turn on TCP/IP keepalive messages */
    set_keepalive (f, 1);
    log_message ("make_tcp_connection: connecting to %s:%hu",
	 inet_ntoa (sin.sin_addr), ntohs (sin.sin_port));
    if (connect (f, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
	if (N_ERRNO != EINPROGRESS
#ifdef WIN32
	    /* winsock returns EWOULDBLOCK even in nonblocking mode! ugh!!! */
	    && N_ERRNO != EWOULDBLOCK
#endif
	    )
	{
	    nlogerr ("make_tcp_connection", "connect");
	    CLOSE (f);
	    return -1;
	}
	log_message ("make_tcp_connection: connection to %s in progress", host);
    }
    else
	log_message ("make_tcp_connection: connection established to %s", host);
    return f;
}

int
check_connect_status (int f)
{
    socklen_t len;
    int     err;

    len = sizeof (err);

    if (getsockopt (f, SOL_SOCKET, SO_ERROR, SOCKOPTCAST & err, &len) != 0)
    {
	nlogerr ("check_connect_status", "getsockopt");
	return -1;
    }
    if (err != 0)
    {
	_logerr ("check_connect_status", "connect", err);
	return -1;
    }
    return 0;
}

char   *
my_ntoa (unsigned int ip)
{
    struct in_addr a;

    a.s_addr = ip;
    return (inet_ntoa (a));
}

#if !defined(WIN32) && !defined(__EMX__)

#ifdef RLIMIT_FDMAX
# define RLIMIT_FD_MAX   RLIMIT_FDMAX
#else
# ifdef RLIMIT_NOFILE
#  define RLIMIT_FD_MAX RLIMIT_NOFILE
# else
#  ifdef RLIMIT_OPEN_MAX
#   define RLIMIT_FD_MAX RLIMIT_OPEN_MAX
#  else
#   undef RLIMIT_FD_MAX
#  endif
# endif
#endif

static int
set_limit (int attr, int value)
{
    struct rlimit lim;

    if (getrlimit (attr, &lim))
    {
	logerr ("set_limit_size", "getrlimit");
	return -1;
    }
    if (lim.rlim_max > 0 && (unsigned int) value > lim.rlim_max)
    {
	/* give feedback to the operator if the default value is lower than
	   requested.  this is important when making the decision as to wheter
	   or not the server needs to be run as uid 0 */
	log_message ("set_limit: warning: %d exceeds default hard limit of %d",
	     value, lim.rlim_max);
    }
    lim.rlim_cur = value;
    if (lim.rlim_max > 0 && lim.rlim_cur > lim.rlim_max)
	lim.rlim_max = lim.rlim_cur;	/* adjust max value */
#ifndef HAVE_POLL
    if (attr == RLIMIT_FD_MAX && lim.rlim_cur > FD_SETSIZE)
    {
	log_message
	    ("set_limit: warning: compiled limit (%d) is smaller than hard limit (%d)",
	     FD_SETSIZE, lim.rlim_max);
    }
#endif /* HAVE_POLL */
    if (setrlimit (attr, &lim))
    {
	logerr ("set_limit", "setrlimit");
	return -1;
    }
    return 0;
}

int
set_max_connections (int n)
{
    if (set_limit (RLIMIT_FD_MAX, n))
    {
	log_message ("set_max_connections: unable to set resource limit");
	return -1;
    }
    log_message ("set_max_connections: max connections set to %d", n);
    return 0;
}

int
set_data_size (int n)
{
    if (set_limit (RLIMIT_DATA, n))
    {
	log_message ("set_data_size: unable to set resource limit");
	return -1;
    }
    log_message ("set_data_size: max data segment size set to %d", n);
    return 0;
}

/* SysVR4 uses RLIMIT_AS (eg. Solaris) */
#ifndef RLIMIT_RSS
#define RLIMIT_RSS RLIMIT_AS
#endif

int
set_rss_size (int n)
{
    if (set_limit (RLIMIT_RSS, n))
    {
	log_message ("set_rss_size: unable to set resource limit");
	return -1;
    }
    log_message ("set_rss_size: max rss segment size set to %d", n);
    return 0;
}
#endif /* !WIN32 */

/* return the local port a socket is bound to */
unsigned short
get_local_port (int fd)
{
    struct sockaddr_in sin;
    socklen_t sinsize = sizeof (sin);

    if (getsockname (fd, (struct sockaddr *) &sin, &sinsize))
    {
	nlogerr ("get_local_port", "getsockname");
	return 0;
    }
    return (ntohs (sin.sin_port));
}

/* table used for is_address */
static unsigned long cidr_to_bitmask[] = {
    /* 00 */ 0x00000000,
    /* 01 */ 0x80000000,
    /* 02 */ 0xC0000000,
    /* 03 */ 0xE0000000,
    /* 04 */ 0xF0000000,
    /* 05 */ 0xF8000000,
    /* 06 */ 0xFC000000,
    /* 07 */ 0xFE000000,
    /* 08 */ 0xFF000000,
    /* 09 */ 0xFF800000,
    /* 10 */ 0xFFC00000,
    /* 11 */ 0xFFE00000,
    /* 12 */ 0xFFF00000,
    /* 13 */ 0xFFF80000,
    /* 14 */ 0xFFFC0000,
    /* 15 */ 0xFFFE0000,
    /* 16 */ 0xFFFF0000,
    /* 17 */ 0xFFFF8000,
    /* 18 */ 0xFFFFC000,
    /* 19 */ 0xFFFFE000,
    /* 20 */ 0xFFFFF000,
    /* 21 */ 0xFFFFF800,
    /* 22 */ 0xFFFFFC00,
    /* 23 */ 0xFFFFFE00,
    /* 24 */ 0xFFFFFF00,
    /* 25 */ 0xFFFFFF80,
    /* 26 */ 0xFFFFFFC0,
    /* 27 */ 0xFFFFFFE0,
    /* 28 */ 0xFFFFFFF0,
    /* 29 */ 0xFFFFFFF8,
    /* 30 */ 0xFFFFFFFC,
    /* 31 */ 0xFFFFFFFE,
    /* 32 */ 0xFFFFFFFF
};

#if 0
static int
bitmask_to_cidr (unsigned int bitmask)
{
    int i;
    for (i = 0; i < 33; i++)
	if (cidr_to_bitmask[i] == bitmask)
	    return i;
    return -1;
}
#endif

/*
 * is_address
 *
 * inputs        - hostname
 *                - pointer to ip result
 *                - pointer to ip_mask result
 * output        - YES if hostname is ip# only NO if its not
 *              - 
 * side effects        - NONE
 * 
 * Thanks Soleil
 * Borrowed from hybrid6 ircd source which is under GNU license.
 *
 * BUGS
 */

int
is_address (char *host, unsigned int *ip_ptr, unsigned int *ip_mask_ptr)
{
    unsigned int current_ip = 0;
    unsigned int octet = 0;
    int     found_mask = 0;
    int     dot_count = 0;
    char    c;

    while ((c = *host))
    {
	if (isdigit (c))
	{
	    octet *= 10;
	    octet += (*host & 0xF);
	}
	else if (c == '.')
	{
	    current_ip <<= 8;
	    current_ip += octet;
	    if (octet > 255)
		return 0;
	    octet = 0;
	    dot_count++;
	}
	else if (c == '/')
	{
	    if (octet > 255)
		return 0;
	    found_mask = 1;
	    while (dot_count <= 3)
	    {
	        current_ip <<= 8;
	        current_ip += octet;
	        octet = 0;
	        dot_count++;
            }
	    *ip_ptr = BSWAP32 (ntohl (current_ip));
	    current_ip = 0L;
	}
	else if (c == '*')
	{
	    if ((dot_count == 3) && (*(host + 1) == '\0')
		&& (*(host - 1) == '.'))
	    {
		while (dot_count <= 3)
		{
	            current_ip <<= 8;
	            dot_count++;
		}
		*ip_ptr = BSWAP32 (ntohl (current_ip));
		*ip_mask_ptr = BSWAP32 (ntohl (0xFFFFFF00L));
		return 1;
	    }
	    else
		return 0;
	}
	else
	    return 0;
	host++;
    }

    if (found_mask)
    {
	current_ip <<= 8;
	current_ip += octet;
	if (current_ip > 32)
	    *ip_mask_ptr = BSWAP32 (ntohl (current_ip));
	else
	    *ip_mask_ptr = BSWAP32 (ntohl (cidr_to_bitmask[current_ip]));
    }
    else
    {
	while (dot_count <= 3)
	{
	    current_ip <<= 8;
	    current_ip += octet;
	    octet = 0;
	    dot_count++;
        }
	*ip_ptr = BSWAP32 (ntohl (current_ip));
	*ip_mask_ptr = 0xffffffff;
    }
    return 1;
}
