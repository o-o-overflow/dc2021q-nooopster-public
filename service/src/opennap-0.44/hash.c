/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
   This is free software disributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id: hash.c,v 1.17 2001/09/23 23:09:04 drscholl Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "hash.h"
#include "debug.h"
#ifdef WIN32
// this is needed for the WIN32 port #def's
#include "opennap.h"
#endif

/* a simple hash table.  */

int
hash_compare_string (void *a, void *b)
{
    return strcmp (a, b) == 0 ? 0 : -1;
}

int
hash_compare_string_insensitive (void *a, void *b)
{
    return strcasecmp (a, b) == 0 ? 0 : -1;
}

/* initialize a hash table.  `buckets' should be a prime number for maximum
   dispersion of entries into buckets */
HASH   *
hash_init (int buckets, hash_destroy f)
{
    HASH   *h = CALLOC (1, sizeof (HASH));

    if (!h)
	return 0;
    h->numbuckets = buckets;
    if ((h->bucket = CALLOC (buckets, sizeof (HASHENT *))) == 0)
    {
	FREE (h);
	return 0;
    }
    h->destroy = f;
    h->hash_key = hash_string;	/* default */
    h->compare_key = hash_compare_string_insensitive;
    return h;
}

void
hash_set_hash_func (HASH * h, hash_key_t f, hash_compare_t comp)
{
    h->hash_key = f;
    h->compare_key = comp;
}

unsigned int
hash_string (void *pkey)
{
    char   *key = (char *) pkey;
    unsigned long h = 0, g;

    ASSERT (key != 0);
    for (; *key; key++)
    {
	h = (h << 4) + tolower (*key);
	if ((g = h & 0xF0000000))
	    h ^= g >> 24;
	h &= ~g;
    }
    return h;
}

unsigned int
hash_pointer (void *key)
{
#if SIZEOF_LONG == 8
#define BITS 3
#else
#define BITS 2
#endif
    return ((u_int) key) >> BITS;
}

unsigned int
hash_u_int (void *key)
{
    return (u_int) key;
}

int
hash_compare_u_int (void *a, void *b)
{
    return (a == b) ? 0 : -1;
}

int
hash_add (HASH * table, void *key, void *data)
{
    HASHENT *he = CALLOC (1, sizeof (HASHENT));
    unsigned int sum;

    if (!he)
	return -1;
    ASSERT (key != 0);
    ASSERT (data != 0);
    ASSERT (table != 0);
    he->key = key;
    he->data = data;
    sum = table->hash_key (key) % table->numbuckets;
    he->next = table->bucket[sum];
    table->bucket[sum] = he;
    table->dbsize++;
    return 0;
}

void   *
hash_lookup (HASH * table, void *key)
{
    HASHENT *he;
    unsigned int sum;

    if (!table)
	return 0;
    ASSERT (key != 0);
    sum = table->hash_key (key) % table->numbuckets;
    he = table->bucket[sum];

    for (; he; he = he->next)
    {
	if (table->compare_key (key, he->key) == 0)
	    return he->data;
    }
    return 0;
}

int
hash_remove (HASH * table, void *key)
{
    HASHENT **he, *ptr;
    unsigned int sum;

    ASSERT (table != 0);
    ASSERT (key != 0);
    sum = table->hash_key (key) % table->numbuckets;
    for (he = &table->bucket[sum]; *he; he = &(*he)->next)
    {
	if (table->compare_key (key, (*he)->key) == 0)
	{
	    ptr = (*he)->next;
	    if (table->destroy)
		table->destroy ((*he)->data);
	    FREE (*he);
	    table->dbsize--;
	    *he = ptr;
	    return 0;
	}
    }
    return -1;
}

void
free_hash (HASH * h)
{
    HASHENT *he, *ptr;
    int     i;

    ASSERT (h != 0);
    /* destroy remaining entries */
    for (i = 0; i < h->numbuckets; i++)
    {
	he = h->bucket[i];
	while (he)
	{
	    ptr = he;
	    he = he->next;
	    if (h->destroy)
		h->destroy (ptr->data);
	    FREE (ptr);
	}
    }
    FREE (h->bucket);
    FREE (h);
}

void
hash_foreach (HASH * h, void (*func) (void *, void *), void *funcdata)
{
    HASHENT *he, *ptr;
    int     i;

    for (i = 0; i < h->numbuckets; i++)
    {
	he = h->bucket[i];
	while (he)
	{
	    /* we use a temp pointer here so that we can remove this entry
	       from the hash table inside of `func' and not cause problems
	       iterating the rest of the bucket */
	    ptr = he;
	    he = he->next;
	    func (ptr->data, funcdata);
	}
    }
}
