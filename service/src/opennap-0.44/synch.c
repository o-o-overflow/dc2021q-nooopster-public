/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id: synch.c,v 1.64 2001/09/22 05:52:06 drscholl Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <time.h>
#include "opennap.h"
#include "debug.h"

char   *Levels[LEVEL_ELITE + 1] = {
    "Leech",
    "User",
    "Moderator",
    "Admin",
    "Elite"
};

static void
sync_user (USER * user, CONNECTION * con)
{
    ASSERT (validate_connection (con));
    ASSERT (validate_user (user));

    /* we should never tell a peer server about a user that is behind
       them */
    ASSERT (user->con != con);
    if (user->con == con)
    {
	/* this really shouldnt happen! */
	ASSERT (0);
	return;
    }

    /* send a login message for this user */
    send_cmd (con, MSG_CLIENT_LOGIN,
	      "%s %s %hu \"%s\" %d unknown %u %u %s %hu", user->nick,
	      user->pass, user->port, user->clientinfo, user->speed,
	      user->connected, user->ip, user->server, user->conport);

    /* update the user's level */
    if (user->level != LEVEL_USER)
    {
	send_cmd (con, MSG_CLIENT_SETUSERLEVEL, ":%s %s %s",
		  Server_Name, user->nick, Levels[user->level]);
    }

    if (user->cloaked)
	send_cmd (con, MSG_CLIENT_CLOAK, ":%s 1", user->nick);

    /* do this before the joins so the user's already in the channel see
       the real file count */
    if (user->shared)
	send_cmd (con, MSG_SERVER_USER_SHARING, "%s %hu %u", user->nick,
		  user->shared, user->libsize);

    /* MUST be after the join's since muzzled users cant join */
    if (user->muzzled)
	send_cmd (con, MSG_CLIENT_MUZZLE, ":%s %s", Server_Name, user->nick);

    /* NOTE: channel joins are handled in sync_channel */
}

static void
sync_chan (CHANNEL * chan, CONNECTION * con)
{
    LIST   *list;

    if (!chan->local)
    {
	for (list = chan->users; list; list = list->next)
	    sync_channel_user (con, chan, list->data);

	if (chan->level != LEVEL_USER)
	    send_cmd (con, MSG_CLIENT_SET_CHAN_LEVEL, ":%s %s %s %u",
		    Server_Name, chan->name, Levels[chan->level],
		    chan->timestamp);
	if (chan->limit != 0)
	    send_cmd (con, MSG_CLIENT_CHANNEL_LIMIT, ":%s %s %d %u",
		    Server_Name, chan->name, chan->limit, chan->timestamp);

	if (chan->flags)
	    send_cmd (con, MSG_CLIENT_CHANNEL_MODE, ":%s %s%s%s%s%s :%u",
		    Server_Name, chan->name,
		    (chan->flags & ON_CHANNEL_PRIVATE) ? " +PRIVATE" : "",
		    (chan->flags & ON_CHANNEL_MODERATED) ? " +MODERATED" : "",
		    (chan->flags & ON_CHANNEL_INVITE) ? " +INVITE" : "",
		    (chan->flags & ON_CHANNEL_TOPIC) ? " +TOPIC" : "",
		    (chan->flags & ON_CHANNEL_REGISTERED) ? " +REGISTERED" : "",
		    chan->timestamp);

	sync_channel_bans (con, chan);
    }
}

static void
sync_server_list (CONNECTION * con)
{
    LIST   *list;
    LINK   *slink;
    CONNECTION *serv;

    /* sync local servers */
    for (list = Servers; list; list = list->next)
    {
	serv = list->data;
	if (serv != con)
	{
	    send_cmd (con, MSG_SERVER_LINK_INFO, "%s %hu %s %hu 2",
		      Server_Name, get_local_port (serv->fd),
		      serv->host, serv->port);
	}
    }

    /* sync remote servers */
    for (list = Server_Links; list; list = list->next)
    {
	slink = list->data;
	send_cmd (con, MSG_SERVER_LINK_INFO, "%s %hu %s %hu %d",
		  slink->server, slink->port, slink->peer, slink->peerport,
		  slink->hops + 1);
    }
}

static void
sync_banlist (CONNECTION * con)
{
    LIST   *list;
    BAN    *b;

    ASSERT (validate_connection (con));
    for (list = Bans; list; list = list->next)
    {
	b = list->data;
	ASSERT (b != 0);
	send_cmd (con, MSG_CLIENT_BAN, ":%s %s \"%s\" %u", Server_Name,
		  b->target, b->reason, b->timeout);
    }
}

void
synch_server (CONNECTION * con)
{
    ASSERT (validate_connection (con));

    log_message ("synch_server: syncing");

    /* send the current time of day to check for clock skew */
    send_cmd (con, MSG_SERVER_TIME_CHECK, ":%s %u",
	      Server_Name, (int) time (&global.current_time));

    sync_server_list (con);
    /* send our peer server a list of all users we know about */
    hash_foreach (Users, (hash_callback_t) sync_user, con);
    /* sync the channel level */
    hash_foreach (Channels, (hash_callback_t) sync_chan, con);
    sync_banlist (con);

    /* sync acls */
    acl_sync (con);

    log_message ("synch_server: done");
}
