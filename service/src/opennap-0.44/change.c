/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id: change.c,v 1.68 2001/09/22 05:52:06 drscholl Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include "opennap.h"
#include "debug.h"

/* user request to change the data port they are listening on.
   703 [ :<user> ] <port> */
HANDLER (change_data_port)
{
    int     port;
    USER   *user;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &user) != 0)
	return;
    ASSERT (validate_user (user));
    port = atoi (pkt);

    /* the official server doesn't seem to check the value sent, so this
       error is unique to this implementation */
    if (port >= 0 && port <= 65535)
    {
	user->port = port;
	pass_message_args (con, tag, ":%s %hu", user->nick, user->port);
    }
    else if (ISUSER (con))
	send_cmd (con, MSG_SERVER_NOSUCH, "invalid data port");
}

/* 700 [ :<user> ] <speed> */
/* client is changing link speed */
HANDLER (change_speed)
{
    USER   *user;
    int     spd;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &user) != 0)
	return;
    spd = atoi (pkt);
    if (spd >= 0 && spd <= 10)
    {
	user->speed = spd;
	pass_message_args (con, tag, ":%s %d", user->nick, spd);
    }
    else if (ISUSER (con))
	send_cmd (con, MSG_SERVER_NOSUCH, "invalid speed");
}

/* 701 [ :<user> ] <password>
   change user password */
HANDLER (change_pass)
{
    USER   *user;
    USERDB *db;

    (void) tag;
    (void) len;
    if (pop_user (con, &pkt, &user) != 0)
	return;
    if (!pkt || !*pkt)
    {
	log_message ("change_pass(): missing new password");
	unparsable (con);
	return;
    }
    /* pass this along even if it is not locally registered.  the user db
     * is distributed so a record for it may reside on another server */
    pass_message_args (con, tag, ":%s %s", user->nick, pkt);
    db = hash_lookup (User_Db, user->nick);
    if (!db)
    {
	log_message ("change_pass(): %s is not registered", user->nick);
	return;
    }
    FREE (db->password);
    db->password = generate_pass (pkt);
    if (ISUSER (con))
	send_cmd (con, MSG_SERVER_NOSUCH, "password changed");
}

/* 702 [ :<user> ] <email>
   change email address */
HANDLER (change_email)
{
#if EMAIL
    USER   *user;
    USERDB *db;

    (void) tag;
    (void) len;
    if (pop_user (con, &pkt, &user) != 0)
	return;
    if (!pkt || !*pkt)
    {
	log_message ("change_email(): missing new email address");
	unparsable (con);
	return;
    }
    pass_message_args (con, tag, ":%s %s", user->nick, pkt);
    db = hash_lookup (User_Db, user->nick);
    if (!db)
    {
	log_message ("change_email(): could not find user %s in the database",
	     user->nick);
	return;
    }
    FREE (db->email);
    db->email = STRDUP (pkt);
#else
    (void) tag;
    (void) len;
    (void) pkt;
    (void) con;
#endif
}

/* 613 [ :<sender> ] <user> <port> [ <reason> ]
   admin request to change a user's data port */
HANDLER (alter_port)
{
    USER   *sender, *user;
    char   *nick, *port;
    int     p;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &sender) != 0)
	return;
    /* check for privilege */
    if (sender->level < LEVEL_MODERATOR)
    {
	log_message ("alter_port(): %s has no privilege to change ports",
	     sender->nick);
	permission_denied (con);
	return;
    }

    nick = next_arg (&pkt);
    port = next_arg (&pkt);
    if (!nick || !port)
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
    p = atoi (port);
    if (p < 0 || p > 65535)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "%d is an invalid port", p);
	return;
    }

    if (pkt)
	truncate_reason (pkt);

    if (user->port != p)
    {
	/* only log when the port value is actually changed, not resets */
	notify_mods (CHANGELOG_MODE, "%s changed %s's data port to %d: %s",
		     sender->nick, user->nick, p, NONULL (pkt));
	user->port = p;
    }

    /* if local user, send them the message */
    if (user->local)
	send_cmd (user->con, MSG_CLIENT_ALTER_PORT, "%d", p);

    pass_message_args (con, tag, ":%s %s %d", sender->nick, user->nick, p);

    log_message ("alter_port: %s set %s's data port to %d", sender->nick,
	 user->nick, p);
}

/* 753 [ :<sender> ] <nick> <pass> ["reason"]
   admin command to change a user's password */
HANDLER (alter_pass)
{
    USER   *sender;
    int     ac = -1;
    char   *av[3];
    char   *sender_name;
    USERDB *db;
    USER	*target;

    ASSERT (validate_connection);
    (void) tag;
    (void) len;
    if (pop_user_server (con, tag, &pkt, &sender_name, &sender))
	return;
    if (sender->level < LEVEL_ADMIN)
    {
	permission_denied (con);
	return;
    }
    if (pkt)
	ac = split_line (av, FIELDS (av), pkt);

    if (ac < 2)
    {
	log_message ("alter_pass(): wrong number of arguments");
	print_args (ac, av);
	unparsable (con);
	return;
    }
    if (invalid_nick (av[0]))
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH,
		      "alter password failed: invalid nickname");
	return;
    }
    target = hash_lookup (Users, av[0]);
    if (target)
    {
	if (target->level >= sender->level)
	{
	    send_cmd (con, MSG_SERVER_NOSUCH,
		    "alter password failed: permission denied");
	    return;
	}
    }

    if (ac > 2)
	truncate_reason (av[2]);
    /* send this now since the account might not be locally registered */
    pass_message_args (con, tag, ":%s %s %s \"%s\"", sender->nick, av[0],
		       av[1], (ac > 2) ? av[2] : "");
    db = hash_lookup (User_Db, av[0]);
    if (db)
    {
	char   *newpass;

	if (db->level >= sender->level)
	{
	    send_cmd (con, MSG_SERVER_NOSUCH,
		    "alter password failed: permission denied");
	    return;
	}
	newpass = generate_pass (av[1]);
	if (!newpass)
	{
	    OUTOFMEMORY ("alter_pass");
	    return;
	}
	FREE (db->password);
	db->password = newpass;
    }
    notify_mods (CHANGELOG_MODE, "%s changed %s's password: %s",
		 sender->nick, av[0], (ac > 2) ? av[2] : "");
}

/* 625 [ :<sender> ] <nick> <speed>
   admin command to change another user's reported line speed */
HANDLER (alter_speed)
{
    USER   *sender, *user;
    int     ac, speed;
    char   *av[2];

    ASSERT (validate_connection (con));
    (void) len;
    if (pop_user (con, &pkt, &sender))
	return;
    ac = split_line (av, sizeof (av) / sizeof (char *), pkt);

    if (ac < 2)
    {
	unparsable (con);
	return;
    }
    if (sender->level < LEVEL_MODERATOR)
    {
	permission_denied (con);
	return;
    }
    speed = atoi (av[1]);
    if (speed < 0 || speed > 10)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "Invalid speed");
	return;
    }
    user = hash_lookup (Users, av[0]);
    if (!user)
    {
	nosuchuser (con);
	return;
    }
    ASSERT (validate_user (user));
    if (user->speed == speed)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "%s's speed is already %d",
		      user->nick, speed);
	return;
    }
    user->speed = speed;
    pass_message_args (con, tag, ":%s %s %d", sender->nick, user->nick,
		       speed);
    notify_mods (CHANGELOG_MODE, "%s changed %s's speed to %d.", sender->nick,
		 user->nick, speed);
}

/* 611 [ :<sender> ] <user> [ <reason> ]
   nuke a user's account */
HANDLER (nuke)
{
    USER   *sender, *user;
    USERDB *db;
    char   *nick, *sender_name;
    int     level = -1;

    ASSERT (validate_connection (con));
    (void) len;
    if (pop_user_server (con, tag, &pkt, &sender_name, &sender))
	return;
    nick = next_arg (&pkt);
    if (!nick)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH,
		      "nuke failed: missing nickname");
	else
	    log_message ("nuke: missing nick (from server %s)", con->host);
	return;
    }

    if (sender && sender->level < LEVEL_MODERATOR)
    {
	send_user (sender, MSG_SERVER_NOSUCH,
		"[%s] nuke failed: permission denied", Server_Name);
	return;
    }

    db = hash_lookup (User_Db, nick);
    user = hash_lookup (Users, nick);

    /* if a user issued this nuke, and the target user is either logged in
     * or exists in the database..
     */
    if (sender && sender->level < LEVEL_ELITE && (db || user))
    {
	/* find the target user's level */
	level = user ? user->level : db->level;

	/* sender's level must be greater than the target's, unless user is
	 * nuking themself for some reason.
	 */
	if (sender->level <= level &&
	    strcasecmp (sender->nick, db ? db->nick : user->nick) != 0)
	{
	    send_user (sender, MSG_SERVER_NOSUCH,
		       "[%s] nuke failed: permission denied", Server_Name);
	    return;
	}
    }

    if (db)
	hash_remove (User_Db, db->nick);

    if (pkt)
	truncate_reason (pkt);

    /* if the user is currently logged in, set them to a sane state (one
     * which would not require a db entry.
     */
    if (user)
    {
	/* if the target user is a mod+, remove them from the Mods list */
	if (user->level >= LEVEL_MODERATOR && ISUSER (user->con))
	{
	    Mods = list_delete (Mods, user->con);
	}

	user->level = LEVEL_USER;
	if (user->cloaked)
	{
	    if (ISUSER (user->con))
	    {
		send_cmd (user->con, MSG_SERVER_NOSUCH,
			  "You are no longer cloaked.");
	    }
	    user->cloaked = 0;
	}
	user->muzzled = 0;
	if (ISUSER (user->con))
	{
	    send_cmd (user->con, MSG_SERVER_NOSUCH,
		      "%s nuked your account: %s",
		      sender && sender->cloaked ? "Operator" : sender_name,
		      NONULL (pkt));
	}
    }

    pass_message_args (con, tag, ":%s %s %s", sender_name, nick,
		       NONULL (pkt));

    notify_mods (CHANGELOG_MODE, "%s nuked %s's account: %s",
		 sender_name, nick, NONULL (pkt));
}

/* 652 [ :<sender> ] [0 | 1]
 * toggle the invisible state of the current user.  when a server is the
 * sender of the message, the 1 signifies that the cloak status should
 * absolutely be turned on rather than toggled (used for synch)
 */
HANDLER (cloak)
{
    USER   *sender;
    int     bit = -1;
    char   *sender_name;
    char   *bitptr;

    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user_server (con, tag, &pkt, &sender_name, &sender))
	return;

    bitptr = next_arg (&pkt);

    if (bitptr)
    {
	bit = atoi (bitptr);
	if (bit > 1 || bit < 0)
	{
	    log_message ("cloak: invalid cloak state %s", bitptr);
	    if (ISUSER (con))
		send_cmd (con, MSG_SERVER_NOSUCH,
			  "cloak failed: invalid cloak state %s", bitptr);
	    return;
	}
    }

    if (bit == -1)
	bit = !sender->cloaked;	/* toggle */

    /* always allow the decloak to go through in order to help fix desyncs */
    if (bit == 1)
    {
	if (sender->level < LEVEL_MODERATOR)
	{
	    send_user (sender, MSG_SERVER_NOSUCH,
		       "[%s] cloak failed: permission denied", Server_Name);
	    if (ISSERVER (con))
	    {
		log_message ("cloak: %s can't cloak, %s desycned", sender->nick,
		     con->host);
		/*force a decloak */
		send_cmd (con, MSG_CLIENT_CLOAK, ":%s 0", sender->nick);
	    }
	    return;
	}
    }

    if ((bit == 1 && sender->cloaked) || (bit == 0 && !sender->cloaked))
	return;			/*no change */

    sender->cloaked = bit;

    /* always send the absolute state when passing server messages */
    pass_message_args (con, tag, ":%s %d", sender->nick, bit);

    notify_mods (CLOAKLOG_MODE, "%s has %scloaked", sender->nick,
		 sender->cloaked ? "" : "de");

    if (ISUSER (con))
	send_cmd (con, MSG_SERVER_NOSUCH, "You are %s cloaked.",
		  sender->cloaked ? "now" : "no longer");
}
