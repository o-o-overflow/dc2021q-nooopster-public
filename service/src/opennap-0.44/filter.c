/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id: filter.c,v 1.15 2001/09/23 23:09:04 drscholl Exp $ */

/* simple filtering mechanism to weed out entries which have too many
 * matches.  this used to be hardcoded, but various servers will need
 * to tailor this to suit their own needs.  see sample.filter for an
 * example list of commonly occuring words
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include "opennap.h"
#include "debug.h"

#ifndef ROUTING_ONLY

#if !defined(HAVE_REGCOMP) || defined(__CYGWIN__)
#include "_regex.h"
#else
#include <regex.h>
#endif

HASH   *Filter = 0;
static LIST *Block = 0;

static void
load_filter_internal (HASH * h, const char *file)
{
    char    path[_POSIX_PATH_MAX];
    char    buf[128], *token;
    int     len;
    FILE   *fp;

    snprintf (path, sizeof (path), "%s/%s", Config_Dir, file);
    fp = fopen (path, "r");
    if (!fp)
    {
	if (errno != ENOENT)
	    log_message ("load_filter_internal: fopen: %s: %s (errno %d)",
		 path, strerror (errno), errno);
	return;
    }
    while (fgets (buf, sizeof (buf) - 1, fp))
    {
	len = strlen (buf);
	while (len > 0 && isspace (buf[len - 1]))
	    len--;
	buf[len] = 0;
	/* need to convert to lowercase since the hash table is
	 * case-sensitive
	 */
	strlower (buf);
	token = STRDUP (buf);
	hash_add (h, token, token);
    }
    fclose (fp);
}

void
load_filter (void)
{
    if (Filter)
	free_hash (Filter);
    Filter = hash_init (257, free_pointer);
    /* set to case-sensitive function for speed.  we always convert to
     * lower case before insertion.
     */
    hash_set_hash_func (Filter, hash_string, hash_compare_string);
    load_filter_internal (Filter, "filter");
}

void
load_block (void)
{
    char    path[_POSIX_PATH_MAX];
    char    buf[256];
    char    err[256];
    char    exp[256];
    int     len;
    FILE   *fp;
    regex_t *rx;
    int     line = 0;
    LIST  **head = &Block;
    int     n;

    log_message ("load_block: free'g old list");

    while (*head)
    {
	LIST   *ptr = *head;

	*head = (*head)->next;
	regfree (ptr->data);
	FREE (ptr);
    }

    snprintf (path, sizeof (path), "%s/block", Config_Dir);
    fp = fopen (path, "r");
    if (!fp)
    {
	if (errno != ENOENT)
	    log_message ("load_block: fopen: %s: %s (errno %d)",
		 path, strerror (errno), errno);
	return;
    }
    log_message ("load_block: reading %s", path);
    while (fgets (buf, sizeof (buf) - 1, fp))
    {
	line++;
	if (buf[0] == '#')
	    continue;
	len = strlen (buf);
	while (len > 0 && isspace (buf[len - 1]))
	    len--;
	buf[len] = 0;
	snprintf (exp, sizeof (exp), "(^|[^[:alpha:]])%s($|[^[:alpha:]])",
		  buf);
	rx = CALLOC (1, sizeof (regex_t));
	if (!rx)
	{
	    OUTOFMEMORY ("load_block");
	    break;
	}
	n = regcomp (rx, exp, REG_EXTENDED | REG_ICASE | REG_NOSUB);
	if (n)
	{
	    err[0] = 0;
	    regerror (n, rx, err, sizeof (err));
	    log_message ("load_block: %s: %d: %s", path, line, err);
	    FREE (rx);
	    continue;
	}
	*head = CALLOC (1, sizeof (LIST));
	(*head)->data = rx;
	head = &(*head)->next;
    }
    fclose (fp);
    log_message ("load_block: done");
}

int
is_filtered (char *s)
{
    return (hash_lookup (Filter, s) != 0);
}

int
is_blocked (char *s)
{
    LIST   *ptr = Block;

    for (; ptr; ptr = ptr->next)
	if (regexec (ptr->data, s, 0, NULL, 0) == 0)
	{
#if 0
	    printf ("is_blocked: match: %s\n", s);
#endif
	    return 1;
	}
    return 0;
}
#endif /* ! ROUTING_ONLY */
