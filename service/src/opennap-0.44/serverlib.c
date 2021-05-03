/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id: serverlib.c,v 1.38 2001/09/22 05:52:06 drscholl Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include "opennap.h"
#include "debug.h"

void
send_cmd (CONNECTION * con, unsigned int msgtype, const char *fmt, ...)
{
    va_list ap;
    size_t  l;

    va_start (ap, fmt);
    vsnprintf (Buf + 4, sizeof (Buf) - 4, fmt, ap);
    va_end (ap);

    set_tag (Buf, msgtype);
    l = strlen (Buf + 4);
    set_len (Buf, l);
    queue_data (con, Buf, 4 + l);
}

/* wrapper for pass_message() */
void
pass_message_args (CONNECTION * con, u_int msgtype, const char *fmt, ...)
{
    va_list ap;
    size_t  l;

    if (!Servers)
	return;			/* nothing to do */

    va_start (ap, fmt);
    vsnprintf (Buf + 4, sizeof (Buf) - 4, fmt, ap);
    va_end (ap);
    set_tag (Buf, msgtype);
    l = strlen (Buf + 4);
    set_len (Buf, l);
    pass_message (con, Buf, 4 + l);
}

/* this function sends a command to an arbitrary user without the caller
   needing to know if its a local client or not */
void
send_user (USER * user, int tag, char *fmt, ...)
{
    int     len, offset;
    va_list ap;

    if (user->local)
    {
	/* deliver directly */
	va_start (ap, fmt);
	vsnprintf (Buf + 4, sizeof (Buf) - 4, fmt, ap);
	va_end (ap);
	set_tag (Buf, tag);
	len = strlen (Buf + 4);
	set_len (Buf, len);
    }
    else
    {
	/* encapsulate and send to remote server */
	snprintf (Buf + 4, sizeof (Buf) - 4, ":%s %s ", Server_Name,
		  user->nick);
	offset = strlen (Buf + 4);
	set_tag (Buf, MSG_SERVER_ENCAPSULATED);
	va_start (ap, fmt);
	vsnprintf (Buf + 8 + offset, sizeof (Buf) - 8 - offset, fmt, ap);
	va_end (ap);
	set_tag (Buf + 4 + offset, tag);
	len = strlen (Buf + 8 + offset);
	set_len (Buf + 4 + offset, len);
	len += offset + 4;
	set_len (Buf, len);
    }
    queue_data (user->con, Buf, len + 4);
}

/* no such user */
void
nosuchuser (CONNECTION * con)
{
    ASSERT (validate_connection (con));
    if (ISUSER (con))
	send_cmd (con, MSG_SERVER_NOSUCH, "User is not currently online.");
}

void
permission_denied (CONNECTION * con)
{
    ASSERT (validate_connection (con));
    if (ISUSER (con))
	send_cmd (con, MSG_SERVER_NOSUCH, "permission denied");
}

/* send a message to all peer servers.  `con' is the connection the message
   was received from and is used to avoid sending the message back from where
   it originated. */
void
pass_message (CONNECTION * con, char *pkt, size_t pktlen)
{
    LIST   *list;

    for (list = Servers; list; list = list->next)
	if (list->data != con)
	    queue_data (list->data, pkt, pktlen);
}

/* destroys memory associated with the CHANNEL struct.  this is usually
   not called directly, but in association with the hash_remove() and
   hash_destroy() calls */
void
free_channel (CHANNEL * chan)
{
    ASSERT (validate_channel (chan));
    FREE (chan->name);
    if (chan->topic)
	FREE (chan->topic);
    ASSERT (chan->users == 0);
    list_free (chan->users, 0);
    list_free (chan->bans, (list_destroy_t) free_ban);
    ASSERT (chan->invited == 0);
    list_free (chan->invited, 0);	/* free invite list */
    FREE (chan);
}

#ifdef DEBUG
int
validate_connection (CONNECTION * con)
{
    /* does not work with mempool */
    ASSERT_RETURN_IF_FAIL (VALID_LEN (con, sizeof (CONNECTION)), 0);
    ASSERT_RETURN_IF_FAIL (con->magic == MAGIC_CONNECTION, 0);
    ASSERT_RETURN_IF_FAIL ((con->class == CLASS_USER) ^ (con->user == 0), 0);
    ASSERT_RETURN_IF_FAIL (VALID_STR (con->host), 0);
    if (con->sendbuf)
	ASSERT_RETURN_IF_FAIL (buffer_validate (con->sendbuf), 0);
    if (con->recvbuf)
	ASSERT_RETURN_IF_FAIL (buffer_validate (con->recvbuf), 0);
    if (ISUSER (con))
    {
	if (con->uopt)
	{
	    ASSERT_RETURN_IF_FAIL (VALID_LEN (con->uopt, sizeof (USEROPT)),
				   0);
	    ASSERT_RETURN_IF_FAIL (list_validate (con->uopt->hotlist), 0);
	}
    }
    return 1;
}

int
validate_user (USER * user)
{
    /* this doesn't work with the mempool since it is an offset into
       a preallocated chunk */
    ASSERT_RETURN_IF_FAIL (VALID_LEN (user, sizeof (USER)), 0);
    ASSERT_RETURN_IF_FAIL (user->magic == MAGIC_USER, 0);
    ASSERT_RETURN_IF_FAIL (VALID_STR (user->nick), 0);
    ASSERT_RETURN_IF_FAIL (VALID_STR (user->clientinfo), 0);
    ASSERT_RETURN_IF_FAIL (user->con == 0
			   || VALID_LEN (user->con, sizeof (CONNECTION)), 0);
    ASSERT_RETURN_IF_FAIL (list_validate (user->channels), 0);
    return 1;
}

int
validate_channel (CHANNEL * chan)
{
    ASSERT_RETURN_IF_FAIL (VALID_LEN (chan, sizeof (CHANNEL)), 0);
    ASSERT_RETURN_IF_FAIL (chan->magic == MAGIC_CHANNEL, 0);
    ASSERT_RETURN_IF_FAIL (VALID_STR (chan->name), 0);
    ASSERT_RETURN_IF_FAIL (list_validate (chan->users), 0);
    return 1;
}
#endif

/* like pop_user(), but allows `nick' to be another server */
int
pop_user_server (CONNECTION * con, int tag, char **pkt, char **nick,
		 USER ** user)
{
    if (ISSERVER (con))
    {
	if (**pkt != ':')
	{
	    log_message
		("pop_user_server: (tag %d) server message missing sender (from %s)",
		 tag, con->host);
	    return -1;
	}
	(*pkt)++;
	*nick = next_arg (pkt);
	if (!is_server (*nick))
	{
	    *user = hash_lookup (Users, *nick);
	    if (!*user)
	    {
		log_message
		    ("pop_user_server: (tag %d) could not find user %s (from %s)",
		     tag, *nick, con->host);
		return -1;
	    }
	}
	else
	    *user = 0;
    }
    else
    {
	ASSERT (ISUSER (con));
	*user = con->user;
	*nick = (*user)->nick;
    }
    return 0;
}

int
pop_user (CONNECTION * con, char **pkt, USER ** user)
{
    ASSERT (validate_connection (con));
    ASSERT (pkt != 0 && *pkt != 0);
    ASSERT (user != 0);
    if (ISSERVER (con))
    {
	char   *ptr;

	if (**pkt != ':')
	{
	    log_message ("pop_user: server message did not contain nick: %s", *pkt);
	    return -1;
	}
	++*pkt;
	ptr = next_arg (pkt);
	*user = hash_lookup (Users, ptr);
	if (!*user)
	{
	    log_message ("pop_user: could not find user %s", ptr);
	    return -1;
	}

	/* this should not return a user who is local to us.  if so, it
	   means that some other server has passed us back a message we
	   sent to them */
	if ((*user)->local)
	{
	    log_message ("pop_user: error, received server message for local user!");
	    return -1;
	}
    }
    else
    {
	ASSERT (con->class == CLASS_USER);
	ASSERT (con->user != 0);
	*user = con->user;
    }
    return 0;

}

void
unparsable (CONNECTION * con)
{
    ASSERT (validate_connection (con));
    if (ISUSER (con))
	send_cmd (con, MSG_SERVER_NOSUCH, "parameters are unparsable");
}

void
nosuchchannel (CONNECTION * con)
{
    ASSERT (validate_connection (con));
    if (ISUSER (con))
	send_cmd (con, MSG_SERVER_NOSUCH, "no such channel");
}

/* returns nonzero if `s' is the name of a server */
int
is_server (const char *s)
{
    LIST   *list;
    CONNECTION *con;
    LINK   *link;

    for (list = Servers; list; list = list->next)
    {
	con = list->data;
	if (!strcasecmp (s, con->host))
	    return 1;
    }
    for (list = Server_Links; list; list = list->next)
    {
	link = list->data;
	if (!strcasecmp (s, link->server) || !strcasecmp (s, link->peer))
	    return 1;
    }
    return 0;
}

/* returns nonzero if `nick' is in list `ignore' */
int
is_ignoring (LIST * ignore, const char *nick)
{
    for (; ignore; ignore = ignore->next)
	if (!strcasecmp (nick, ignore->data))
	    return 1;
    return 0;
}

void
invalid_channel_msg (CONNECTION * con)
{
    ASSERT (validate_connection (con));
    if (ISUSER (con))
	send_cmd (con, MSG_SERVER_NOSUCH, "invalid channel");
}

void
truncate_reason (char *s)
{
    if (Max_Reason > 0 && strlen (s) > (unsigned) Max_Reason)
	*(s + Max_Reason) = 0;
}

void
invalid_nick_msg (CONNECTION * con)
{
    if (ISUSER (con))
	send_cmd (con, MSG_SERVER_NOSUCH, "invalid nickname");
}

CONNECTION *
new_connection (void)
{
    CONNECTION *c = CALLOC (1, sizeof (CONNECTION));

    if (!c)
    {
	OUTOFMEMORY ("new_connection");
	return 0;
    }
#ifdef DEBUG
    c->magic = MAGIC_CONNECTION;
#endif
    return c;
}

static int
vform_message (char *d, int dsize, int tag, const char *fmt, va_list ap)
{
    int     len;

    vsnprintf (d + 4, dsize - 4, fmt, ap);
    len = strlen (d + 4);
    set_tag (d, tag);
    set_len (d, len);
    return (len + 4);
}

int
form_message (char *d, int dsize, int tag, const char *fmt, ...)
{
    va_list ap;
    int     len;

    va_start (ap, fmt);
    len = vform_message (d, dsize, tag, fmt, ap);
    va_end (ap);
    return len;
}

void
send_cmd_pre (CONNECTION * con, unsigned int tag, const char *prefix,
	      const char *fmt, ...)
{
    va_list ap;
    int     len;

    va_start (ap, fmt);
    /* if the user's client supports use of real numerics send the raw */
    if (con->numerics)
	len = vform_message (Buf, sizeof (Buf), tag, fmt, ap);
    else
    {
	/*otherwise prefix it with a descriptive string and send it as a 404 */
	strncpy (Buf + 4, prefix, sizeof (Buf) - 4);
	len = strlen (Buf + 4);
	vsnprintf (Buf + 4 + len, sizeof (Buf) - 4 - len, fmt, ap);
	len += strlen (Buf + 4 + len);
	set_tag (Buf, MSG_SERVER_NOSUCH);
	set_len (Buf, len);
	len += 4;
    }
    queue_data (con, Buf, len);
    va_end (ap);
}
