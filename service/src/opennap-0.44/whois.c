/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.
 
   $Id: whois.c,v 1.62 2001/09/22 05:52:06 drscholl Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

/* this is nasty but a necessary evil to avoid using a static buffer */
char   *
append_string (char *in, const char *fmt, ...)
{
    va_list ap;

    va_start (ap, fmt);
    vsnprintf (Buf, sizeof (Buf), fmt, ap);
    va_end (ap);
    if (!in)
	return STRDUP (Buf);
    else
    {
	int     len = strlen (in);

	if (safe_realloc ((void **) &in, len + strlen (Buf) + 1))
	    return 0;
	strcpy (in + len, Buf);
	return in;
    }
}

/* 604 <user> */
HANDLER (whois)
{
    USER   *sender, *user;
    time_t  online;
    LIST   *chan;
    USERDB *db;
    char   *cap;
    char   *rsp = 0;
    char   *nick;

    (void) tag;
    (void) len;
    CHECK_USER_CLASS ("whois");
    sender = con->user;
    ASSERT (validate_connection (con));
    nick = next_arg (&pkt);
    if (!nick)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "whois failed: missing nickname");
	return;
    }
    user = hash_lookup (Users, nick);
    if (!user)
    {
	/* check to see if this is a registered nick */
	db = hash_lookup (User_Db, nick);
	if (db)
	    send_cmd (con, MSG_SERVER_WHOWAS, "%s \"%s\" %u", db->nick,
		      Levels[db->level], db->lastSeen);
	else
	    send_cmd (con, MSG_SERVER_NOSUCH,
		      "user %s is not a known user", nick);
	nosuchuser (con);
	return;
    }

    ASSERT (validate_user (user));

    online = (int) (global.current_time - user->connected);

    rsp = append_string (rsp, "%s", user->nick);
    rsp = append_string (rsp, " \"%s\"", Levels[user->level]);
    rsp = append_string (rsp, " %u", (int) online);
    rsp = append_string (rsp, " \" ");
    /* always show channel membership to privileged users */
    if (!user->cloaked || sender->level > LEVEL_USER)
    {
	for (chan = user->channels; chan; chan = chan->next)
	{
	    if ((((CHANNEL *) chan->data)->flags & ON_CHANNEL_PRIVATE) == 0)
		rsp =
		    append_string (rsp, "%s ",
				   ((CHANNEL *) chan->data)->name);
	}
    }
    rsp = append_string (rsp, "\"");	/* terminate the channel list */

    if (user->muzzled)
	cap = "Muzzled";
    else if (user->cloaked && sender->level > LEVEL_USER)
	cap = "Cloaked";	/* show cloaked state to privileged users */
    else
	cap = "Active";
    rsp = append_string (rsp, " \"%s\"", cap);
    rsp = append_string (rsp, " %d %d %d %d", user->shared, user->downloads,
			 user->uploads, user->speed);
    rsp = append_string (rsp, " \"%s\"", user->clientinfo);

    /* moderators and above see some additional information */
    if (sender->level > LEVEL_USER)
    {
	db = hash_lookup (User_Db, user->nick);
	rsp = append_string (rsp, " %d %d %s %hu %hu",
			     user->totaldown, user->totalup,
			     my_ntoa (BSWAP32 (user->ip)),
			     user->conport, user->port);
#if EMAIL
#define EmailAddr(db) db?db->email:"unknown"
#else
#define EmailAddr(db) "unknown"
#endif
	rsp = append_string (rsp, " %s", EmailAddr (db));
    }
    /* admins and above see the server the user is connected to.  this is
       only admin+ since the windows client would likely barf if present.
       i assume that admin+ will use another client such as BWap which
       understands the extra field */
    if (sender->level > LEVEL_MODERATOR)
	rsp =
	    append_string (rsp, " %s",
			   user->server ? user->server : Server_Name);
    send_user (sender, MSG_SERVER_WHOIS_RESPONSE, "%s", rsp);
    FREE (rsp);

    /* notify privileged users when someone requests their info */
    if (user->level >= LEVEL_MODERATOR && sender != user)
    {
	ASSERT (validate_connection (user->con));

	if (ISUSER (user->con))
	{
	    if (user->con->uopt->usermode & WHOISLOG_MODE)
		send_cmd (user->con, MSG_SERVER_NOSUCH,
			  "%s has requested your info", con->user->nick);
	}
	else
	{
	    /* relay the whois notifcation to the target's server.  doing
	     * this as a separate message allows us to do a usermode -whois
	     * to turn off this messge if the user doesn't care to see it.
	     */
	    send_cmd (user->con, MSG_SERVER_WHOIS_NOTIFY, ":%s %s",
		      con->user->nick, user->nick);
	}
    }
}

/* 10024 :<sender> <nick>
 * remote whois notification
 */
HANDLER (whois_notify)
{
    char   *sender_name;
    USER   *sender;
    USER   *target;
    char   *nick;

    (void) len;
    CHECK_SERVER_CLASS("whois_notify");
    if (pop_user_server (con, tag, &pkt, &sender_name, &sender))
	return;
    nick = next_arg (&pkt);
    if (!nick)
    {
	log_message ("whois_notify: missing argument");
	return;
    }
    target = hash_lookup (Users, nick);
    if (!target)
    {
	log_message ("whois_notify: %s: no such user", nick);
	return;
    }
    if (ISUSER (target->con))
    {
	if (target->con->uopt->usermode & WHOISLOG_MODE)
	    send_cmd (target->con, MSG_SERVER_NOSUCH,
		      "%s has requested your info", sender_name);
    }
    else
	send_cmd (target->con, tag, ":%s %s", sender_name, target->nick);
}

/* 10119 <user>
 * display which server a particular user is on
 */
HANDLER (which_server)
{
    USER   *user;
    char   *nick;

    (void) tag;
    (void) len;
    CHECK_USER_CLASS ("which_server");
    /* leeches are bad, mmmkay? */
    if (con->user->level < LEVEL_USER)
    {
	send_cmd (con, MSG_SERVER_ERROR,
		  "which server failed: permission denied");
	return;
    }
    nick = next_arg (&pkt);
    if (!nick)
    {
	send_cmd (con, MSG_SERVER_ERROR,
		  "which server failed: missing nick");
	return;
    }
    user = hash_lookup (Users, nick);
    if (!user)
    {
	send_cmd (con, MSG_SERVER_NOSUCH,
		  "which server failed: no such user");
	return;
    }
    if (ISUSER (user->con))
	send_cmd (con, MSG_SERVER_NOSUCH, "%s is on %s", user->nick,
		  user->server);
    else
	send_cmd (con, MSG_SERVER_NOSUCH, "%s is on %s (via %s)", user->nick,
		  user->server, user->con->host);
}

/* 10121 <user>
 * who-was
 */
HANDLER (who_was)
{
    char   *nick = next_arg (&pkt);
    whowas_t *who;

    (void) len;
    CHECK_USER_CLASS ("who_was");
    if (!nick)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "who was failed: missing nickname");
	return;
    }
    if (con->user->level < LEVEL_MODERATOR)
    {
	send_cmd (con, MSG_SERVER_NOSUCH,
		  "who was failed: permission denied");
	return;
    }
    who = hash_lookup (Who_Was, nick);
    if (!who)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "who was failed: %s: no info",
		  nick);
	return;
    }
    send_cmd (con, tag, "%s %u %s %u \"%s\"", who->nick, BSWAP32 (who->ip),
	    who->server, who->when, who->clientinfo);
}

void
free_whowas (whowas_t * who)
{
    if (who)
    {
	if (who->nick)
	    FREE (who->nick);
	FREE (who);
    }
}

static void
expire_whowas_cb (whowas_t * who, void *unused)
{
    (void) unused;
    if (global.current_time - who->when >= Who_Was_Time)
    {
	/* entry is old, remove it */
	hash_remove (Who_Was, who->nick);
    }
}

void
expire_whowas (void)
{
    log_message ("expire_whowas: expiring old info");
    hash_foreach (Who_Was, (hash_callback_t) expire_whowas_cb, 0);
    log_message ("expire_whowas: %d nicks in the cache", Who_Was->dbsize);

    /* not really any better place to do this, so put it here for now */
    cleanup_ip_info ();
}
