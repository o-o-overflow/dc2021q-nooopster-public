/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id: browse.c,v 1.48 2001/09/20 06:58:59 drscholl Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "opennap.h"
#include "debug.h"

#ifndef ROUTING_ONLY

typedef struct
{
    short   count;
    short   max;
    USER   *sender;
    USER   *user;
}
BROWSE;

static void
browse_callback (DATUM * info, BROWSE * ctx)
{
    /* avoid flooding the client */
    if (ctx->max == 0 || ctx->count < ctx->max)
    {
	send_user (ctx->sender, MSG_SERVER_BROWSE_RESPONSE,
		   "%s \"%s\" %s %u %hu %hu %hu",
		   info->user->nick, info->filename,
#if RESUME
		   info->hash,
#else
		   "00000000000000000000000000000000",
#endif
		   info->size,
		   BitRate[info->bitrate], SampleRate[info->frequency],
		   info->duration);

	ctx->count++;
    }
}

#endif /* ! ROUTING_ONLY */

/* 211 [ :<sender> ] <nick> [ <max> ]
   browse a user's files */
HANDLER (browse)
{
    USER   *sender, *user;
    char   *nick;
    int     result;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &sender))
	return;
    nick = next_arg (&pkt);
    if (!nick)
    {
	unparsable (con);
	return;
    }
    if (invalid_nick (nick))
    {
	invalid_nick_msg (con);
	return;
    }
    user = hash_lookup (Users, nick);
    if (!user)
    {
	if (ISUSER (con))
	{
	    /* the napster servers send a 210 instead of 404 for this case */
	    send_cmd (con, MSG_SERVER_USER_SIGNOFF, "%s", nick);
	    /* always terminate the list */
	    send_cmd (con, MSG_SERVER_BROWSE_END, "%s", nick);
	}
	return;
    }
    ASSERT (validate_user (user));

    if (pkt)
    {
	result = atoi (pkt);
	if (result == 0 ||
	    (Max_Browse_Result > 0 && result > Max_Browse_Result))
	    result = Max_Browse_Result;
    }
    else
	result = Max_Browse_Result;

    if (!option (ON_REMOTE_BROWSE) &&
	    (!ISUSER (sender->con) || !ISUSER (user->con)))
    {
	/* remote browsing is not supported */
	send_user (sender, MSG_SERVER_BROWSE_END, "%s %u",
		user->nick, (user->shared > 0) ? user->ip : 0);
	return;
    }

    if (ISUSER (user->con))
    {
#ifndef ROUTING_ONLY
	if (user->con->uopt->files)
	{
	    BROWSE  data;

	    data.count = 0;
	    data.user = user;
	    data.sender = sender;
	    data.max = pkt ? atoi (pkt) : 0;
	    if (Max_Browse_Result > 0 && data.max > Max_Browse_Result)
		data.max = Max_Browse_Result;
	    hash_foreach (user->con->uopt->files,
			  (hash_callback_t) browse_callback, &data);
	}
#endif /* ! ROUTING_ONLY */
	
	/* send end of browse list message */
	send_user (sender, MSG_SERVER_BROWSE_END, "%s %u", user->nick,
		   /* don't send the ip if the user isn't sharing - security */
		   user->shared > 0 ? user->ip : 0);
    }
    else
    {
	/* relay to the server that this user is connected to */
	send_cmd (user->con, tag, ":%s %s %d", sender->nick, user->nick,
		  result);
    }
}

/* deprecated - clients should do direct browsing with 640 now.  this was
 * causing too much cpu use for users with large amounts of shared files
 */
#if 0
#ifndef ROUTING_ONLY
static void
create_file_list (DATUM * d, LIST ** p)
{
    DATUM  *f;

    while (*p)
    {
	f = (*p)->data;
	if (strcasecmp (d->filename, f->filename) <= 0)
	{
	    LIST   *n = CALLOC (1, sizeof (LIST));

	    n->data = d;
	    n->next = *p;
	    *p = n;
	    return;
	}
	p = &(*p)->next;
    }
    *p = CALLOC (1, sizeof (LIST));
    (*p)->data = d;
}

static char *
last_slash (char *s)
{
    /* const */ char *p;

    for (;;)
    {
	p = strpbrk (s + 1, "/\\");
	if (!p)
	    return s;
	s = p;
    }
}

static char *
dirname (char *d, int dsize, /* const */ char *s)
{
    char   *p;

    strncpy (d, s, dsize - 1);
    d[dsize - 1] = 0;
    p = last_slash (d);
    *p = 0;
    return d;
}

static char *
my_basename (char *d, int dsize, /* const */ char *s)
{
    s = last_slash (s);
    strncpy (d, s + 1, dsize - 1);
    d[dsize - 1] = 0;
    return d;
}
#endif /* ! ROUTING_ONLY */

/* 10301 [ :<sender> ] <nick>
   new browse requst */
HANDLER (browse_new)
{
    USER   *sender, *user;
    char   *nick;
    int     results = -1;

    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &sender))
	return;
    nick = next_arg (&pkt);
    if (!nick)
    {
	unparsable (con);
	return;
    }
    user = hash_lookup (Users, nick);
    if (!user)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "browse failed: no such user");
	send_user (sender, tag, "%s 0", nick);	/* always terminate */
	return;
    }

    if (pkt)
    {
	results = atoi (pkt);
	if (Max_Browse_Result > 0 && results > Max_Browse_Result)
	    results = Max_Browse_Result;
    }
    else
	results = Max_Browse_Result;

    if (ISUSER (user->con))
    {
#ifndef ROUTING_ONLY
	if (user->con->uopt->files)
	{
	    LIST   *list = 0, *tmpList;
	    char    dir[_POSIX_PATH_MAX];
	    char    path[_POSIX_PATH_MAX];
	    char    base[_POSIX_PATH_MAX];
	    char   *rsp = 0;
	    int     count = 0;

	    hash_foreach (user->con->uopt->files,
			  (hash_callback_t) create_file_list, &list);
	    dir[0] = 0;
	    if (results == 0)
		results = 0x7fffffff;	/* hack, we really mean unlimited */
	    for (tmpList = list; tmpList && results;
		 tmpList = tmpList->next, results--)
	    {
		DATUM  *d = tmpList->data;

		dirname (path, sizeof (path), d->filename);
		my_basename (base, sizeof (base), d->filename);
		if (count < 5 && dir[0] && !strcasecmp (dir, path))
		{
		    /* same directory as previous result, append */
		    rsp = append_string (rsp, " \"%s\" %s %u %d %d %d", base,
#if RESUME
					 d->hash,
#else
					 "0",
#endif
					 d->size,
					 BitRate[d->bitrate],
					 SampleRate[d->frequency],
					 d->duration);
		    if (!rsp)
			break;
		    count++;
		}
		else
		{
		    /* new directory */
		    strcpy (dir, path);
		    if (rsp)
		    {
			/* send off the previous buffer command */
			send_user (sender, MSG_SERVER_BROWSE_RESULT_NEW, "%s",
				   rsp);
			FREE (rsp);
		    }
		    rsp = append_string (0, "%s \"%s\" \"%s\" %s %u %d %d %d",
					 user->nick, dir, base,
#if RESUME
					 d->hash,
#else
					 "0",
#endif
					 d->size,
					 BitRate[d->bitrate],
					 SampleRate[d->frequency],
					 d->duration);
		    if (!rsp)
			break;
		    count = 0;
		}
	    }
	    list_free (list, 0);

	    if (rsp)
	    {
		send_user (sender, MSG_SERVER_BROWSE_RESULT_NEW, "%s", rsp);
		FREE (rsp);
	    }
	}
#endif /* ! ROUTING_ONLY */
	/* terminate the list */
	send_user (sender, tag, "%s %u", user->nick,
		   /* don't give out ip if not sharing anything - security */
		   user->shared > 0 ? user->ip : 0);
    }
    else
    {
	/* relay the request to the server where this user is connected */
	send_cmd (user->con, tag, ":%s %s %d", sender->nick, user->nick,
		  results);
    }
}
#endif

/* 640 [:sender] nick
 * direct browse request
 */
HANDLER (browse_direct)
{
    char   *sender_name, *nick;
    USER   *sender, *user;

    (void) len;
    if (pop_user_server (con, tag, &pkt, &sender_name, &sender))
	return;
    nick = next_arg (&pkt);
    if (!nick)
    {
	unparsable (con);
	return;
    }
    user = hash_lookup (Users, nick);
    if (!user)
    {
	nosuchuser (con);
	return;
    }

    if (ISUSER (con))
    {
	if (sender->port == 0 && user->port == 0)
	{
	    send_cmd (con, MSG_SERVER_BROWSE_DIRECT_ERR,
		      "%s \"Both you and %s are firewalled; you cannot browse or download from them.\"",
		      user->nick, user->nick);
	    return;
	}
	else if (user->shared == 0)
	{
	    send_cmd (con, MSG_SERVER_BROWSE_DIRECT_ERR,
		      "%s \"%s is not sharing any files.\"",
		      user->nick, user->nick);
	    return;
	}
    }

    if (ISUSER (user->con))
    {
	if (!is_ignoring (user->con->uopt->ignore, sender->nick))
	{
	    if (user->port == 0)
	    {
		/* client being browsed is firewalled.  send full info so
		 * a back connection to the browser can be made.
		 */
		send_cmd (user->con, MSG_CLIENT_BROWSE_DIRECT, "%s %u %hu",
			sender_name, sender->ip, sender->port);
	    }
	    else
	    {
		/* directly connected to this server */
		send_cmd (user->con, MSG_CLIENT_BROWSE_DIRECT, "%s",
			sender_name);
	    }
	}
	else
	    send_cmd (con, MSG_SERVER_BROWSE_DIRECT_ERR,
		    "%s \"%s is not online.\"", user->nick, user->nick);
    }
    else
	send_cmd (user->con, MSG_CLIENT_BROWSE_DIRECT, ":%s %s", sender_name,
		user->nick);
}

/* 641 [:sender] nick
 * direct browse accept
 */
HANDLER (browse_direct_ok)
{
    char   *sender_name, *nick;
    USER   *sender, *user;

    (void) len;
    if (pop_user_server (con, tag, &pkt, &sender_name, &sender))
	return;
    nick = next_arg (&pkt);
    if (!nick)
    {
	unparsable (con);
	return;
    }
    user = hash_lookup (Users, nick);
    if (!user)
    {
	nosuchuser (con);
	return;
    }
    if (ISUSER (user->con))
    {
	/* directly connected to this server */
	send_cmd (user->con, MSG_SERVER_BROWSE_DIRECT_OK, "%s %u %hu",
		  sender->nick, sender->ip, sender->port);
    }
    else
	send_cmd (user->con, MSG_SERVER_BROWSE_DIRECT_OK, ":%s %s",
		  sender_name, user->nick);
}
