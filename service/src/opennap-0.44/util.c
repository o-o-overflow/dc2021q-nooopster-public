/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id: util.c,v 1.103 2001/09/22 05:52:06 drscholl Exp $

   This file contains various utility functions useful elsewhere in this
   server */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#ifndef WIN32
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include "md5.h"
#include "opennap.h"
#include "debug.h"

/* writes `val' as a two-byte value in little-endian format */
void
set_val (char *d, unsigned short val)
{
    val = BSWAP16 (val);
    memcpy (d, &val, 2);
}

/* this is like strtok(2), except that all fields are returned as once.  nul
   bytes are written into `pkt' and `template' is updated with pointers to
   each field in `pkt' */
/* returns: number of fields found. */
int
split_line (char **template, int templatecount, char *pkt)
{
    int     i = 0;

    if (!pkt)
	return -1;
    while (ISSPACE (*pkt))
	pkt++;
    while (*pkt && i < templatecount)
    {
	if (*pkt == '"')
	{
	    /* quoted string */
	    pkt++;
	    template[i++] = pkt;
	    pkt = strchr (pkt, '"');
	    if (!pkt)
	    {
		/* bogus line */
		return -1;
	    }
	    *pkt++ = 0;
	    if (!*pkt)
		break;
	    pkt++;		/* skip the space */
	}
	else
	{
	    template[i++] = pkt;
	    pkt = strpbrk (pkt, " \t\r\n");
	    if (!pkt)
		break;
	    *pkt++ = 0;
	}
	while (ISSPACE (*pkt))
	    pkt++;
    }
    return i;
}

#ifndef ROUTING_ONLY
/* this is like split_line(), except it splits a directory specification into
   path specification and filename, based on the prefix to the believed name
   of the actual file */
/* returns: pointer to filename */
char   *
split_filename (char *fqfn)
{
    char   *lastptr, *firstptr = fqfn;
    int     i = 0, mode = 0;

    if (!fqfn)
	return NULL;
    while (ISSPACE (*fqfn))
	fqfn++;
    while (*fqfn)
    {
	if (!mode)
	{
	    if (*fqfn == '/')
		mode = 1;
	    if (*fqfn == 92)
		mode = 2;
	}
	fqfn++;
    }
    lastptr = fqfn;
    while (fqfn-- > firstptr && i < Index_Path_Depth)
    {
	switch (mode)
	{
	case 1:		/* UNIX Spec */
	    if (*fqfn == '/')
	    {
		lastptr = (fqfn + 1) ? (fqfn + 1) : fqfn;
		i++;
	    }
	    break;

	case 2:		/* DOS Spec */
	    if (*fqfn == 92)
	    {
		lastptr = (fqfn + 1) ? (fqfn + 1) : fqfn;
		i++;
	    }
	    break;
	}
    }
    return lastptr;
}
#endif /* ! ROUTING_ONLY */

static char hex[] = "0123456789ABCDEF";

void
expand_hex (char *v, int vsize)
{
    int     i;

    for (i = vsize - 1; i >= 0; i--)
    {
	v[2 * i + 1] = hex[v[i] & 0xf];
	v[2 * i] = hex[(v[i] >> 4) & 0xf];
    }
}

void
init_random (void)
{
    ASSERT (global.current_time != 0);

    /* force generation of a different seed if respawning quickly by adding
       the pid of the current process */
    srand (global.current_time + getuid () + getpid ());
}

void
get_random_bytes (char *d, int dsize)
{
    int     i = 0, v;

    while (i < dsize)
    {
	v = rand ();
	d[i++] = v & 0xff;
	if (i < dsize)
	    d[i++] = (v >> 8) & 0xff;
	if (i < dsize)
	    d[i++] = (v >> 16) & 0xff;
	if (i < dsize)
	    d[i++] = (v >> 24) & 0xff;
    }
}

    /* generate our own nonce value */
char   *
generate_nonce (void)
{
    char   *nonce;

    nonce = MALLOC (17);
    if (!nonce)
    {
	OUTOFMEMORY ("generate_nonce");
	return 0;
    }
    nonce[16] = 0;

    get_random_bytes (nonce, 8);

    /* expand the binary data into hex for transport */
    expand_hex (nonce, 8);

    return nonce;
}

CHANNEL *
new_channel (void)
{
    CHANNEL *c = CALLOC (1, sizeof (CHANNEL));

    if (!c)
    {
	OUTOFMEMORY ("new_channel");
	return 0;
    }
#ifdef DEBUG
    c->magic = MAGIC_CHANNEL;
#endif
    return c;
}

char   *
strfcpy (char *dest, const char *src, size_t destlen)
{
    strncpy (dest, src, destlen);
    dest[destlen - 1] = 0;
    return dest;
}

#if LOG_CHANNEL
static int Logging = 0;
#endif

void
log_message (const char *fmt, ...)
{
    va_list ap;

#if LOG_CHANNEL
    char    buf[1024];
    int     len;
    char   *msg;

    strfcpy (buf + 4, "&LOG opennap ", sizeof (buf) - 4);
    len = strlen (buf + 4);
    msg = buf + len + 4;
    va_start (ap, fmt);
    vsnprintf (buf + 4 + len, sizeof (buf) - 4 - len, fmt, ap);
    va_end (ap);

    /* prevent infinite loop */
    if (!Logging)
    {
	len += strlen (buf + 4 + len);
	set_tag (buf, MSG_SERVER_PUBLIC);
	set_len (buf, len);

	Logging = 1;
	(void) send_to_channel ("&LOG", buf, len + 4);
	Logging = 0;
    }

    /* display log msg on console */
    fputs (msg, stdout);
#else
    va_start (ap, fmt);
    vprintf (fmt, ap);
    va_end (ap);
#endif
    fputc ('\n', stdout);
    fflush (stdout);
}

/* like next_arg(), except we don't skip over additional whitespace */
char   *
next_arg_noskip (char **s)
{
    char   *r = *s;

    *s = strchr (r, ' ');
    if (*s)
	*(*s)++ = 0;
    return r;
}

char   *
next_arg (char **s)
{
    char   *r = *s;

    if (!r)
	return 0;
    while (ISSPACE (*r))
	r++;
    if (!*r)
	return 0;
    if (*r == '"')
    {
	r++;
	*s = strchr (r, '"');
    }
    else
	*s = strpbrk (r, " \t\r\n");
    if (*s)
    {
	*(*s)++ = 0;
	while (ISSPACE (**s))
	    ++ * s;
	if (!**s)
	    *s = 0;		/* no more arguments */
    }
    return r;
}

char   *
strlower (char *s)
{
    char   *r = s;

    ASSERT (s != 0);
    while (*s)
	*s++ = tolower ((unsigned char) *s);
    return r;
}

int
safe_realloc (void **ptr, int bytes)
{
    void   *t;

    t = REALLOC (*ptr, bytes);
    if (!t)
	return -1;
    *ptr = t;
    return 0;
}

void
print_args (int ac, char **av)
{
    int     i;

    printf ("print_args(): [%d]", ac);
    for (i = 0; i < ac; i++)
	printf (" \"%s\"", av[i]);
    fputc ('\n', stdout);
}

static char alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
#define alphabet(c) alphabet[(unsigned int)c]

static int
b64_encode (char *out, int *outsize, char *in, int insize)
{
    unsigned char a, b, c, d;
    char   *pout = out;

    while (insize > 0)
    {
	c = d = 0xff;
	a = (*in >> 2) & 0x3f;
	b = (*in & 0x3) << 4;
	in++;
	insize--;
	if (insize)
	{
	    b |= (*in >> 4) & 0xf;
	    c = (*in & 0xf) << 2;
	    in++;
	    insize--;
	    if (insize)
	    {
		c |= (*in >> 6) & 0x3;
		d = *in & 0x3f;
		in++;
		insize--;
	    }
	}
	*out++ = alphabet (a);
	*out++ = alphabet (b);
	if (c != 0xff)
	{
	    *out++ = alphabet (c);
	    if (d != 0xff)
		*out++ = alphabet (d);
	    else
		*out++ = '=';
	}
	else
	{
	    *out++ = '=';
	    *out++ = '=';
	}
    }
    *out = 0;
    *outsize = out - pout;
    return 0;
}

static char b64_lookup[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1
};

#define b64_lookup(c) b64_lookup[(unsigned int)c]

static int
b64_decode (char *out, int *outsize, const char *in)
{
    unsigned char a, b, c, d;
    unsigned char b2, b3;
    char   *pout = out;

    while (*in)
    {
	a = b64_lookup (*in++);
	b = b64_lookup (*in++);
	*out++ = a << 2 | b >> 4;
	b2 = b << 4;
	if (*in && *in != '=')
	{
	    c = b64_lookup (*in++);
	    b2 |= c >> 2;
	    *out++ = b2;
	    b3 = c << 6;
	    if (*in && *in != '=')
	    {
		d = b64_lookup (*in++);
		b3 |= d;
		*out++ = b3;
	    }
	    else
		break;
	}
	else
	    break;
    }
    *outsize = out - pout;
    return 0;
}

int
check_pass (const char *info, const char *pass)
{
    struct md5_ctx md;
    char    hash[16], real[16];
    int     realsize;

    ASSERT (info != 0);
    ASSERT (pass != 0);
    if (*info != '1' || *(info + 1) != ',')
	return -1;
    info += 2;
    md5_init_ctx (&md);
    md5_process_bytes (info, 8, &md);
    info += 8;
    if (*info != ',')
	return -1;
    info++;
    md5_process_bytes (pass, strlen (pass), &md);
    md5_finish_ctx (&md, hash);
    realsize = sizeof (real);
    b64_decode (real, &realsize, info);
    ASSERT (realsize == 16);
    if (memcmp (real, hash, 16) == 0)
	return 0;
    return -1;
}

char   *
generate_pass (const char *pass)
{
    struct md5_ctx md;
    char    hash[16];
    char    output[36];		/* 1,xxxxxxxx,xxxxxxxxxxxxxxxxxxxxxxx== */
    int     outsize;
    int     i;

    ASSERT (pass != 0);
    output[0] = '1';
    output[1] = ',';
    get_random_bytes (output + 2, 8);
    for (i = 0; i < 8; i++)
	output[i + 2] = alphabet[((unsigned int) output[i + 2]) % 64];
    output[10] = ',';
    md5_init_ctx (&md);
    md5_process_bytes (output + 2, 8, &md);
    md5_process_bytes (pass, strlen (pass), &md);
    md5_finish_ctx (&md, hash);
    outsize = sizeof (output) - 11;
    b64_encode (output + 11, &outsize, hash, 16);
    output[sizeof (output) - 3] = 0;	/* strip the trailing == */
    return (STRDUP (output));
}

CHANNEL *
find_channel (LIST * channels, const char *s)
{
    for (; channels; channels = channels->next)
	if (!strcasecmp (((CHANNEL *) channels->data)->name, s))
	    return channels->data;
    return 0;
}

void
free_pointer (void *p)
{
    FREE (p);
}

/* check to make sure this string is a valid host name.  include the glob
 * characters
 */
int
invalid_host (const char *p)
{
    while (*p)
    {
	if (!isalnum (*p) || !strchr (".-?*", *p))
	    return 1;
	p++;
    }
    return 0;
}
