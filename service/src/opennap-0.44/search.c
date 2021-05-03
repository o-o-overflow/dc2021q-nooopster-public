/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id: search.c,v 1.135 2001/09/28 22:55:14 drscholl Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <limits.h>
#include "opennap.h"
#include "debug.h"

/* number of searches performed */
unsigned int Search_Count = 0;

/* structure used when handing a search for a remote user */
typedef struct
{
    CONNECTION *con;		/* connection to user that issused the search,
				   or the server they are connected to if
				   remote */
    char   *nick;		/* user who issued the search */
    char   *id;			/* the id for this search */
    short   count;		/* how many ACKS have been recieved? */
    short   numServers;		/* how many servers were connected at the time
				   this search was issued? */
    time_t  timestamp;		/* when the search request was issued */
}
DSEARCH;

static LIST *Remote_Search = 0;

/* keep a pointer to the end of the list for fast append */
static LIST **Remote_Search_Tail = &Remote_Search;

/* keep count of how many searches we are waiting for */
unsigned int Pending_Searches = 0;

static void
search_end (CONNECTION * con, const char *id)
{
    if (ISUSER (con))
    {
	if (con->uopt->searches <= 0)
	{
	    log_message ("search_end: ERROR, con->uopt->searches <= 0!!!!!!");
	    con->uopt->searches = 0;
	}
	else
	    con->uopt->searches--;
	send_cmd (con, MSG_SERVER_SEARCH_END, "");
    }
    else
    {
	send_cmd (con, MSG_SERVER_REMOTE_SEARCH_END, "%s", id);
    }
}

static void
free_dsearch (DSEARCH * d)
{
    if (d)
    {
	if (d->id)
	    FREE (d->id);
	if (d->nick)
	    FREE (d->nick);
	FREE (d);
    }
}

static char *
generate_search_id (void)
{
    char   *id = MALLOC (9);
    int     i;

    if (!id)
    {
	OUTOFMEMORY ("generate_search_id");
	return 0;
    }
    for (i = 0; i < 8; i++)
	id[i] = 'A' + (rand () % 26);
    id[8] = 0;
    return id;
}

/* initiate a distributed search request.  `con' is where we received the
 * request from (could be from a locally connected user or from another
 * server.  `user' is the end-client that issued the search originally,
 * `id' is the search id if receieved from a peer server, NULL if from
 * a locally connected client.  `request' is the search string received from
 * the client indicating what results they want.
 */
static int
dsearch_alloc (CONNECTION * con, USER * user, const char *id,
	       const char *request)
{
    DSEARCH *dsearch;
    LIST   *ptr;

    /* generate a new request structure */
    dsearch = CALLOC (1, sizeof (DSEARCH));
    if (!dsearch)
    {
	OUTOFMEMORY ("search_internal");
	return -1;
    }
    dsearch->timestamp = global.current_time;
    if (id)
    {
	if ((dsearch->id = STRDUP (id)) == 0)
	{
	    OUTOFMEMORY ("search_internal");
	    FREE (dsearch);
	    return -1;
	}
    }
    /* local client issued the search request, generate a new search id so
     * that we can route the results from peer servers back to the correct
     * user
     */
    else if ((dsearch->id = generate_search_id ()) == 0)
    {
	FREE (dsearch);
	return -1;
    }
    dsearch->con = con;
    if (!(dsearch->nick = STRDUP (user->nick)))
    {
	OUTOFMEMORY ("search_internal");
	free_dsearch (dsearch);
	return -1;
    }

    /* keep track of how many replies we expect back */
    dsearch->numServers = list_count (Servers);
    /* if we recieved this from a server, we expect 1 less reply since
       we don't send the search request back to the server that issued
       it */
    if (ISSERVER (con))
	dsearch->numServers--;

    ptr = CALLOC (1, sizeof (LIST));
    if (!ptr)
    {
	OUTOFMEMORY ("search_internal");
	free_dsearch (dsearch);
	return -1;
    }
    ptr->data = dsearch;

    /* append search to the tail of the list. */
    *Remote_Search_Tail = ptr;
    Remote_Search_Tail = &ptr->next;

    Pending_Searches++;

    /* pass this message to all servers EXCEPT the one we recieved
       it from (if this was a remote search) */
    pass_message_args (con, MSG_SERVER_REMOTE_SEARCH, "%s %s %s",
		       user->nick, dsearch->id, request);

    return 0;
}

#ifndef ROUTING_ONLY

/* parameters for searching */
typedef struct
{
    CONNECTION *con;		/* connection for user that issued search */
    USER   *user;		/* user that issued the search */
    int     minbitrate;
    int     maxbitrate;
    int     minfreq;
    int     maxfreq;
    int     minspeed;
    int     maxspeed;
    unsigned int minsize;
    unsigned int maxsize;
    int     minduration;
    int     maxduration;
    int     type;		/* -1 means any type */
    char   *id;			/* if doing a remote search */
}
SEARCH;

/* returns nonzero if there is already the token specified by `s' in the
   list */
static int
duplicate (LIST * list, const char *s)
{
    ASSERT (s != 0);
    for (; list; list = list->next)
    {
	ASSERT (list->data != 0);
	if (!strcmp (s, list->data))
	    return 1;
    }
    return 0;
}

/* consider the apostrophe to be part of the word since it doesn't make
   sense on its own */
#define WORD_CHAR(c) \
	(isalnum((unsigned char)(c))||(c)=='\''||(unsigned char)(c) > 128)

/* return a list of word tokens from the input string.  if excludes != NULL,
 * consider words prefixed with a minus (`-') to be excluded words, and
 * return them in a separate list
 */
LIST   *
tokenize (char *s, LIST ** exclude_list)
{
    LIST   *r = 0, **cur = &r;
    char   *ptr;
    int     exclude;

    /* there may be existing entries, find the end of the list */
    if (exclude_list)
	while (*exclude_list)
	    exclude_list = &(*exclude_list)->next;

    while (*s)
    {
	exclude = 0;
	while (*s && !WORD_CHAR (*s))
	{
	    /* XXX this will catch stupid things like  "- -fast" or
	     * "- slow", but we'll make it fast for the basic case instead
	     * of worrying about it.
	     */
	    if (exclude_list && *s == '-')
		exclude = 1;
	    s++;
	}
	ptr = s;
	while (WORD_CHAR (*ptr))
	    ptr++;
	if (*ptr)
	    *ptr++ = 0;
	strlower (s);		/* convert to lower case to save time */

	/* don't bother with common words, if there is more than 5,000 of
	   any of these it doesnt do any good for the search engine because
	   it won't match on them.  its doubtful that these would narrow
	   searches down any even after the selection of the bin to search */
	/* new dynamic table from config file */
	if (is_filtered (s))
	{
	    s = ptr;
	    continue;
	}

	/* don't add duplicate tokens to the list.  this will cause searches
	   on files that have the same token more than once to show up how
	   ever many times the token appears in the filename */
	if ((!exclude && duplicate (r, s)) ||
	    (exclude && duplicate (*exclude_list, s)))
	{
	    s = ptr;
	    continue;
	}

	if (exclude)
	{
	    *exclude_list = CALLOC (1, sizeof (LIST));
	    if (!*exclude_list)
	    {
		OUTOFMEMORY ("tokenize");
		return r;
	    }
	    (*exclude_list)->data = s;
	    exclude_list = &(*exclude_list)->next;
	}
	else
	{
	    *cur = CALLOC (1, sizeof (LIST));
	    if (!*cur)
	    {
		OUTOFMEMORY ("tokenize");
		return r;
	    }
	    (*cur)->data = s;
	    cur = &(*cur)->next;
	}

	s = ptr;
    }
    return r;
}

/* remove this datum from the lists for each keyword it is indexed under */
void
free_datum (DATUM * d)
{
    int i;
    TokenRef *ref;

    for (i = 0; i < d->numTokens; i++)
    {
	ref = &d->tokens[i];

	ASSERT (validate_flist (ref->flist));

	/* de-link the element pointing to this file */
	if (ref->dlist->prev)
	    ref->dlist->prev->next = ref->dlist->next;
	else
	{
	    /* this is the head of the list, update the flist struct.  if
	     * we just free this pointer, the flist struct would have a bogus
	     * pointer
	     */
	    ref->flist->list = ref->dlist->next;
	}

	/* update the back pointer of the next element (if it exists) */
	if (ref->dlist->next)
	    ref->dlist->next->prev = ref->dlist->prev;

	FREE (ref->dlist);

	ref->flist->count--;
	/* if there are no more files in this bin, erase it */
	if (ref->flist->count == 0)
	{
	    ASSERT (ref->flist->list == 0);
	    hash_remove (File_Table, ref->flist->key);
	    FREE (ref->flist->key);
	    FREE (ref->flist);
	}
    }

    FREE (d->tokens);

    /* XXX broken */
#if RESUME
    flist = hash_lookup (MD5, d->hash);
    if (flist)
    {
	ASSERT (validate_flist (flist));
	flist->list = list_delete (flist->list, d);
	flist->count--;
	/* if there are no more files in this bin, erase it */
	if (flist->count == 0)
	{
	    ASSERT (flist->list == 0);
	    hash_remove (MD5, flist->key);
	    FREE (flist->key);
	    FREE (flist);
	}
    }
    else
	log_message ("free_datum: error, no hash entry for file %s", d->filename);
    FREE (d->hash);
#endif

    FREE (d->filename);
    FREE (d);
}

static int
sContainsFileList (DATUM *d, FileList *f)
{
    int i;

    for (i = 0; i < d->numTokens; i++)
	if (d->tokens[i].flist == f)
	    return 1;
    return 0;
}

static int
fdb_search (LIST * contains, LIST * excludes, int maxhits, SEARCH * crit)
{
    LIST   *words = 0;		/* matched words */
    LIST   *exclude_words = 0;	/* words NOT to match */
    LIST **listptr;
    LIST   *list;		/* temp pointer for creation of `words' list */
    LIST   *pWords;		/* iteration pointer for `words' list */
    DList   *ptok;
    FileList  *flist = 0, *tmp;
    DATUM  *d;
    int     hits = 0;
    int     is_match;

    Search_Count++;

    if (!contains)
    {
	/* this shouldn't happen because we catch this condition down where
	 * fdb_search() is called and report it back to the user
	 */
	log_message ("fdb_search: error, tokens==NULL");
	return 0;
    }

    /* find the file list with the fewest files in it */
    listptr = &words;
    for (list = contains; list; list = list->next)
    {
	tmp = hash_lookup (File_Table, list->data);
	if (!tmp)
	{
	    /* if there is no entry for this word in the hash table, then
	       we know there are no matches */
	    return 0;
	}
	ASSERT (validate_flist (tmp));
	/* keep track of the flist with the fewest entries in it.  we use
	 * this below to refine the search.  we use the smallest subset
	 * of possible matches to narrow the search down.
	 */
	if (!flist || tmp->count < flist->count)
	    flist = tmp;
	else if (flist->count >= File_Count_Threshold)
	{
	    log_message ("fdb_search: token \"%s\" contains %d files",
		 flist->key, flist->count);
	}

	/* keep track of the list of search terms to match.  we use this
	 * later to ensure that all of these tokens appear in the files we
	 * are considering as possible matches
	 */
	*listptr = CALLOC (1, sizeof (LIST));
	if (!*listptr)
	{
	    OUTOFMEMORY ("fdb_search");
	}
	else
	{
	    (*listptr)->data = tmp;	/* current word */
	    listptr = &(*listptr)->next;
	}
    }

    /* find the list of words to exclude, if any */
    listptr = &exclude_words;
    for (list = excludes; list; list = list->next)
    {
	tmp = hash_lookup (File_Table, list->data);
	if (tmp)
	{
	    *listptr = CALLOC (1, sizeof (LIST));
	    if (!*listptr)
	    {
		OUTOFMEMORY ("fdb_search");
	    }
	    else
	    {
		(*listptr)->data = tmp;
		listptr = &(*listptr)->next;
	    }
	}
    }

    /* find the list of files which contain all search tokens.  we do this
     * by iterating the smallest list of files from each of the matched
     * search terms.  for each file in that list, ensure the file is a member
     * of each of the other lists as well
     */
    for (ptok = flist->list; ptok; ptok = ptok->next)
    {
	/* current file to match */
	d = (DATUM *) ptok->data;

	/* make sure each search token listed in `words' is present for
	 * each member of this list.  i am assuming the number of search
	 * tokens is smaller than the number of tokens for a given file.
	 * each element of `words' is an FLIST containing all the matching
	 * files
	 */
	is_match = 1;
	for (pWords = words; pWords; pWords = pWords->next)
	{
	    /* each DATUM contains a list of all the tokens it contains.
	     * check to make sure the current search term is a member
	     * of the list.  skip the word we are matching on since we
	     * know its there.
	     */
	    if (pWords->data != flist &&
		    !sContainsFileList (d, pWords->data))
	    {
		is_match = 0;
		break;
	    }
	}

	if (!is_match)
	    continue;

	/* check to make sure this file doesn't contain any of the excluded
	 * words
	 */
	for (pWords = exclude_words; pWords; pWords = pWords->next)
	{
	    if (sContainsFileList (d, pWords->data))
	    {
		/* file contains a bad word */
		is_match = 0;
		break;
	    }
	}

	if (!is_match)
	    continue;

	/* don't return matches for a user's own files */
	if (d->user == crit->user)
	    continue;
	/* ignore match if both parties are firewalled */
	if (crit->user->port == 0 && d->user->port == 0)
	    continue;
	if (BitRate[d->bitrate] < crit->minbitrate)
	    continue;
	if (BitRate[d->bitrate] > crit->maxbitrate)
	    continue;
	if (d->user->speed < crit->minspeed)
	    continue;
	if (d->user->speed > crit->maxspeed)
	    continue;
	if (d->size < crit->minsize)
	    continue;
	if (d->size > crit->maxsize)
	    continue;
	if (d->duration < crit->minduration)
	    continue;
	if (d->duration > crit->maxduration)
	    continue;
	if (SampleRate[d->frequency] < crit->minfreq)
	    continue;
	if (SampleRate[d->frequency] > crit->maxfreq)
	    continue;
	if (crit->type != -1 && crit->type != d->type)
	    continue;		/* wrong content type */

	/* send the result to the server that requested it */
	if (crit->id)
	{
	    ASSERT (ISSERVER (crit->con));
	    ASSERT (validate_user (d->user));
	    /* 10016 <id> <user> "<filename>" <md5> <size> <bitrate> <frequency> <duration> */
	    send_cmd (crit->con, MSG_SERVER_REMOTE_SEARCH_RESULT,
		      "%s %s \"%s\" %s %u %d %d %d",
		      crit->id, d->user->nick, d->filename,
#if RESUME
		      d->hash,
#else
		      "00000000000000000000000000000000",
#endif
		      d->size, BitRate[d->bitrate],
		      SampleRate[d->frequency], d->duration);
	}
	/* if a local user issued the search, notify them of the match */
	else
	{
	    send_cmd (crit->con, MSG_SERVER_SEARCH_RESULT,
		      "\"%s\" %s %u %d %d %d %s %u %d", d->filename,
#if RESUME
		      d->hash,
#else
		      "00000000000000000000000000000000",
#endif
		      d->size,
		      BitRate[d->bitrate],
		      SampleRate[d->frequency],
		      d->duration,
		      d->user->nick, d->user->ip, d->user->speed);
	}

	/* filename matches, check other criteria */
	if (++hits == maxhits)
	    break;
    }

    list_free (words, 0);

    return hits;
}

static void
generate_qualifier (char *d, int dsize, char *attr, unsigned int min,
		    unsigned int max, unsigned int hardmax)
{
    if (min > 0)
	snprintf (d, dsize, " %s \"%s\" %d",
		  attr, (min == max) ? "EQUAL TO" : "AT LEAST", min);
    else if (max < hardmax)
	snprintf (d, dsize, " %s \"AT BEST\" %d", attr, max);
}

#define MAX_SPEED 10
#define MAX_BITRATE 0xffff
#define MAX_FREQUENCY 0xffff
#define MAX_DURATION 0xffff
#define MAX_SIZE 0xffffffff

static void
generate_request (char *d, int dsize, int results, LIST * contains,
		  LIST * excludes, SEARCH * parms)
{
    int     l;

    snprintf (d, dsize, "FILENAME CONTAINS \"");
    l = strlen (d);
    d += l;
    dsize -= l;
    for (; contains; contains = contains->next)
    {
	snprintf (d, dsize, "%s ", (char *) contains->data);
	l = strlen (d);
	d += l;
	dsize -= l;
    }
    snprintf (d, dsize, "\" MAX_RESULTS %d", results);
    l = strlen (d);
    d += l;
    dsize -= l;
    if (parms->type != CT_MP3)
    {
	snprintf (d, dsize, " TYPE %s",
		  parms->type != -1 ? Content_Types[parms->type] : "ANY");
	l = strlen (d);
	d += l;
	dsize -= l;
    }
    generate_qualifier (d, dsize, "BITRATE", parms->minbitrate,
			parms->maxbitrate, MAX_BITRATE);
    l = strlen (d);
    d += l;
    dsize -= l;
    generate_qualifier (d, dsize, "FREQ", parms->minfreq, parms->maxfreq,
			MAX_FREQUENCY);
    l = strlen (d);
    d += l;
    dsize -= l;
    generate_qualifier (d, dsize, "LINESPEED", parms->minspeed,
			parms->maxspeed, MAX_SPEED);
    l = strlen (d);
    d += l;
    dsize -= l;
    generate_qualifier (d, dsize, "SIZE", parms->minsize,
			parms->maxsize, MAX_SIZE);
    l = strlen (d);
    d += l;
    dsize -= l;
    generate_qualifier (d, dsize, "DURATION", parms->minduration,
			parms->maxduration, MAX_DURATION);
    l = strlen (d);
    d += l;
    dsize -= l;

    if (excludes)
    {
	snprintf (d, dsize, " FILENAME EXCLUDES \"");
	l = strlen (d);
	d += l;
	dsize -= l;
	for (; excludes; excludes = excludes->next)
	{
	    snprintf (d, dsize, "%s ", (char *) excludes->data);
	    l = strlen (d);
	    d += l;
	    dsize -= l;
	}
	snprintf (d, dsize, "\"");
	l = strlen (d);
	d += l;
	dsize -= l;
    }
}

static int
set_compare (CONNECTION * con, const char *op, int val, int *min, int *max)
{
    ASSERT (validate_connection (con));
    ASSERT (min != NULL);
    ASSERT (max != NULL);
    if (!strcasecmp (op, "equal to"))
	*min = *max = val;
    else if (!strcasecmp (op, "at least"))
	*min = val;
    else if (!strcasecmp (op, "at best"))
	*max = val;
    else if (ISUSER (con))
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "%s: invalid comparison for search",
		  op);
	return 1;
    }
    return 0;
}

/* common code for local and remote searching */
static void
search_internal (CONNECTION * con, USER * user, char *id, char *pkt)
{
    int     i, n, max_results = Max_Search_Results, done = 1, local = 0;
    int     invalid = 0;
    LIST   *contains = 0;
    LIST   *excludes = 0;
    SEARCH  parms;
    char   *arg, *arg1, *ptr;

    ASSERT (validate_connection (con));

    /* set defaults */
    memset (&parms, 0, sizeof (parms));
    parms.con = con;
    parms.user = user;
    parms.maxspeed = MAX_SPEED;
    parms.maxbitrate = MAX_BITRATE;
    parms.maxfreq = MAX_FREQUENCY;
    parms.maxsize = MAX_SIZE;
    parms.maxduration = MAX_DURATION;
    parms.type = CT_MP3;	/* search for audio/mp3 by default */
    parms.id = id;

    /* prime the first argument */
    arg = next_arg (&pkt);
    while (arg)
    {
	if (!strcasecmp ("filename", arg))
	{
	    arg = next_arg (&pkt);
	    arg1 = next_arg (&pkt);
	    if (!arg || !arg1)
	    {
		invalid = 1;
		goto done;
	    }
	    /* do an implicit AND operation if multiple FILENAME CONTAINS
	       clauses are specified */
	    if (!strcasecmp ("contains", arg))
		contains = list_append (contains, tokenize (arg1, &excludes));
	    else if (!strcasecmp ("excludes", arg))
		/* ignore `-' prefix here */
		excludes = list_append (excludes, tokenize (arg1, NULL));
	    else
	    {
		invalid = 1;
		goto done;
	    }
	}
	else if (!strcasecmp ("max_results", arg))
	{
	    arg = next_arg (&pkt);
	    if (!arg)
	    {
		invalid = 1;
		goto done;
	    }
	    max_results = strtol (arg, &ptr, 10);
	    if (*ptr)
	    {
		/* not a number */
		invalid = 1;
		goto done;
	    }
	    if ((Max_Search_Results > 0 && max_results > Max_Search_Results)
		    /* don't let the user pick 0 to force unlimited results! */
		    || max_results == 0)
		max_results = Max_Search_Results;
	}
	else if (!strcasecmp ("type", arg))
	{
	    arg = next_arg (&pkt);
	    if (!arg)
	    {
		invalid = 1;
		goto done;
	    }
	    parms.type = -1;
	    if (strcasecmp ("any", arg))
	    {
		for (n = CT_MP3; n < CT_UNKNOWN; n++)
		{
		    if (!strcasecmp (arg, Content_Types[n]))
		    {
			parms.type = n;
			break;
		    }
		}
		if (parms.type == -1)
		{
		    if (ISUSER (con))
			send_cmd (con, MSG_SERVER_NOSUCH,
				  "%s: invalid type for search", arg);
		    goto done;
		}
	    }
	}
	else if ((!strcasecmp ("linespeed", arg) && (i = 1)) ||
		 (!strcasecmp ("bitrate", arg) && (i = 2)) ||
		 (!strcasecmp ("freq", arg) && (i = 3)) ||
		 (!strcasecmp ("size", arg) && (i = 4)) ||
		 (!strcasecmp ("duration", arg) && (i = 5)))
	{
	    int    *min, *max;

	    arg = next_arg (&pkt);	/* comparison operation */
	    arg1 = next_arg (&pkt);	/* value */
	    if (!arg || !arg1)
	    {
		invalid = 1;
		goto done;
	    }
	    n = strtol (arg1, &ptr, 10);
	    if (*ptr)
	    {
		/* not a number */
		invalid = 1;
		goto done;
	    }
	    if (i == 1)
	    {
		min = &parms.minspeed;
		max = &parms.maxspeed;
	    }
	    else if (i == 2)
	    {
		min = &parms.minbitrate;
		max = &parms.maxbitrate;
	    }
	    else if (i == 3)
	    {
		min = &parms.minfreq;
		max = &parms.maxfreq;
	    }
	    else if (i == 4)
	    {
		min = (int *) &parms.minsize;
		max = (int *) &parms.maxsize;
	    }
	    else if (i == 5)
	    {
		min = &parms.minduration;
		max = &parms.maxduration;
	    }
	    else
	    {
		log_message ("fdb_search: ERROR, drscholl fucked up if you see this");
		goto done;
	    }

	    if (set_compare (con, arg, n, min, max))
		goto done;
	}
	else if (!strcasecmp ("local", arg)
		 || !strcasecmp ("local_only", arg))
	{
	    local = 1;		/* only search for files from users on the same server */
	}
	else
	{
	    log_message ("search: %s: unknown search argument", arg);
	    invalid = 1;
	    goto done;
	}
	arg = next_arg (&pkt);	/* skip to next token */
    }

    if (!contains)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH,
		      "search failed: request contained no valid words");
	goto done;
    }

    n = fdb_search (contains, excludes, max_results, &parms);

    if ((n < max_results) && !local &&
	((ISSERVER (con) && list_count (Servers) > 1) ||
	 (ISUSER (con) && Servers)))
    {
	char   *request;

	/* reform the search request to send to the remote servers */
	generate_request (Buf, sizeof (Buf), max_results - n, contains,
			  excludes, &parms);
	/* make a copy since pass_message_args() uses Buf[] */
	request = STRDUP (Buf);

	if (dsearch_alloc (con, user, id, request))
	{
	    FREE (request);
	    goto done;
	}

	FREE (request);
	done = 0;		/* delay sending the end-of-search message */
    }

  done:

    if (invalid)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "invalid search request");
    }

    list_free (contains, 0);
    list_free (excludes, 0);

    if (done)
	search_end (con, id);
}

/* 200 ... */
HANDLER (search)
{
    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("search");

    /* if Max_Searches is > 0, we only allow clients to have a certain small
     * number of pending search requests.  Some abusive clients will tend
     * to issues multiple search requests at a time.
     */
    if (con->uopt->searches < 0)
    {
	log_message ("search: ERROR, con->uopt->searches < 0!!!");
	send_cmd (con, MSG_SERVER_NOSUCH, "search failed: server error");
	con->uopt->searches = 0;
	return;
    }

    if (! option (ON_ALLOW_SHARE))
    {
	/* sharing is not allowed on this server */
	send_cmd (con, MSG_SERVER_SEARCH_END, "");
	return;
    }

    /* if Max_Searches is > 0, we only allow clients to have a certain small
     * number of pending search requests.  Some abusive clients will tend
     * to issues multiple search requests at a time.
     */
    if (Max_Searches > 0 && con->uopt->searches >= Max_Searches)
    {
	send_cmd (con, MSG_SERVER_NOSUCH,
		  "search failed: too many pending searches");
	return;
    }
    if (con->uopt->searches == 0x7fffffff)
    {
	log_message ("search: ERROR, con->uopt->searches will overflow!!!");
	send_cmd (con, MSG_SERVER_NOSUCH, "search failed: server error");
	return;
    }
    con->uopt->searches++;
    search_internal (con, con->user, 0, pkt);
}
#endif /* ! ROUTING_ONLY */

static DSEARCH *
find_search (const char *id)
{
    LIST   *list;
    DSEARCH *ds;

    for (list = Remote_Search; list; list = list->next)
    {
	ASSERT (list->data != 0);
	ds = list->data;
	if (!strcmp (ds->id, id))
	    return ds;
    }
    return 0;
}

/* 10015 <sender> <id> ...
   remote search request */
HANDLER (remote_search)
{
    USER   *user;
    char   *nick, *id;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_SERVER_CLASS ("remote_search");
    nick = next_arg (&pkt);	/* user that issued the search */
    id = next_arg (&pkt);
    if (!nick || !id || !pkt)
    {
	/* try to terminate the search anyway */
	if (id)
	    send_cmd (con, MSG_SERVER_REMOTE_SEARCH_END, "%s", id);
	log_message ("remote_search: too few parameters");
	return;
    }
    user = hash_lookup (Users, nick);
    if (!user)
    {
	log_message ("remote_search: could not locate user %s (from %s)", nick,
	     con->host);
	/* imediately notify the peer that we don't have any matches */
	send_cmd (con, MSG_SERVER_REMOTE_SEARCH_END, "%s", id);
	return;
    }

    if (! option (ON_ALLOW_SHARE))
    {
	/* sharing is not allowed on this server */
	send_cmd (con, MSG_SERVER_REMOTE_SEARCH_END, "%s", id);
	return;
    }

#ifdef ROUTING_ONLY
    Search_Count++;
    /* no local files, just pass this request to the peer servers and
     * wait for the reponses
     */
    if (dsearch_alloc (con, user, id, pkt))
    {
	/* failed, send the ACK back immediately */
	send_cmd (con, MSG_SERVER_REMOTE_SEARCH_END, "%s", id);
    }
#else
    search_internal (con, user, id, pkt);
#endif
}

/* 10016 <id> <user> "<filename>" <md5> <size> <bitrate> <frequency> <duration>
   send a search match to a remote user */
HANDLER (remote_search_result)
{
    DSEARCH *search;
    char   *av[8];
    int     ac;
    USER   *user;

    (void) con;
    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_SERVER_CLASS ("remote_search_result");
    ac = split_line (av, sizeof (av) / sizeof (char *), pkt);

    if (ac != 8)
    {
	log_message ("remote_search_result: wrong number of args");
	print_args (ac, av);
	return;
    }
    search = find_search (av[0]);
    if (!search)
    {
	log_message ("remote_search_result: could not find search id %s", av[0]);
	return;
    }
    if (ISUSER (search->con))
    {
	/* deliver the match to the client */
	user = hash_lookup (Users, av[1]);
	if (!user)
	{
	    log_message ("remote_search_result: could not find user %s (from %s)",
		 av[1], con->host);
	    return;
	}
	send_cmd (search->con, MSG_SERVER_SEARCH_RESULT,
		  "\"%s\" %s %s %s %s %s %s %u %d",
		  av[2], av[3], av[4], av[5], av[6], av[7], user->nick,
		  user->ip, user->speed);
    }
    else
    {
	/* pass the message back to the server we got the request from */
	ASSERT (ISSERVER (search->con));
	/* should not send it back to the server we just recieved it from */
	ASSERT (con != search->con);
	send_cmd (search->con, tag, "%s %s \"%s\" %s %s %s %s %s",
		  av[0], av[1], av[2], av[3], av[4], av[5], av[6], av[7]);
    }
}

/* consolodated code for removing a pending search struct from the list.
 * this needs to be done from several points, so aggregate the command code
 * here.  Note that *list gets updated, so its perfectly fine to loop on
 * it when calling this routine.
 */
static void
unlink_search (LIST ** list, int send_ack)
{
    DSEARCH *s = (*list)->data;
    LIST   *tmp;

    ASSERT (validate_connection (s->con));
    if (send_ack)
	search_end (s->con, s->id);
    free_dsearch (s);
    tmp = *list;
    *list = (*list)->next;
    /* if there are no more entries in the list, we have to update the
     * tail pointer
     */
    if (!*list)
	Remote_Search_Tail = list;
    FREE (tmp);

    if (Pending_Searches == 0)
	log_message ("search_end: ERROR, Pending_Searches == 0!!!");
    else
	Pending_Searches--;
}

/* 10017 <id>
   indicates end of search results for <id> */
HANDLER (remote_search_end)
{
    DSEARCH *search;
    LIST  **list;
    char   *id = next_arg (&pkt);

    CHECK_SERVER_CLASS ("remote_search_end");

    ASSERT (validate_connection (con));
    (void) con;
    (void) tag;
    (void) len;

    list = &Remote_Search;
    while (*list)
    {
	if (!strcmp (((DSEARCH *) (*list)->data)->id, id))
	    break;
	list = &(*list)->next;
    }
    if (!*list)
    {
	log_message ("remote_end_match: could not find entry for search id %s", id);
	return;
    }
    search = (*list)->data;
    ASSERT (search->numServers <= list_count (Servers));
    search->count++;
    if (search->count == search->numServers)
    {
	/* got the end of the search matches from all our peers, clean up */
	unlink_search (list, 1);
    }
}

/* if a user logs out before the search is complete, we need to cancel
   the search so that we don't try to send the result to the client */
void
cancel_search (CONNECTION * con)
{
    LIST  **list;
    DSEARCH *d;
    int     isServer = ISSERVER (con);

    ASSERT (validate_connection (con));
    list = &Remote_Search;
    while (*list)
    {
	d = (*list)->data;
	if (isServer)
	    d->numServers--;
	if (d->con == con || d->count >= d->numServers)
	    /* this call updates *list, so we don't have to worry about an
	     * inifinite loop
	     */
	    unlink_search (list, (d->con != con));
	else
	    list = &(*list)->next;
    }
}

void
expire_searches (void)
{
    LIST  **list = &Remote_Search;
    DSEARCH *search;
    int     expired = 0;

    while (*list)
    {
	search = (*list)->data;
	if (search->timestamp + Search_Timeout > global.current_time)
	    break;		/* everything else in the list is older, so we
				   can safely stop here */
	/* this call updates *list, so we don't have to worry about an
	 * inifinite loop
	 */
	unlink_search (list, 1);
	expired++;
    }
    if (expired)
	log_message ("expire_searches: %d stale entries", expired);
}
