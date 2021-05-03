/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id: login.c,v 1.191 2001/09/22 05:52:06 drscholl Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "opennap.h"
#include "hashlist.h"
#include "debug.h"

int
invalid_nick (const char *s)
{
    int     count = 0;
    LIST   *list;
    server_auth_t *auth;

    /* don't allow anyone to ever have this nick */
    if (!strcasecmp (s, "operserv") || !strcasecmp (s, "chanserv") ||
	!strcasecmp (s, "operator") || !strcasecmp (s, "nickserv"))
	return 1;
    /* check to make sure a user isn't attempting to use an alias of one
     * of our peer servers.  we don't need to check the full dns name because
     * nicks already can't contain a period (.)
     */
    for (list = Server_Auth; list; list = list->next)
    {
	auth = list->data;
	if (auth->alias && !strcasecmp (auth->alias, s))
	    return 1;
    }
    if (strchr ("#&:-", *s))
	return 1;		/* nick can't begin with # or & (denotes a channel) */
    while (*s)
    {
	if (*s < '!' || *s > '~' || strchr ("%$*?.!\",\\", *s))
	    return 1;
	count++;
	s++;
    }
    /* enforce min/max nick length */
    return (count == 0 || (Max_Nick_Length > 0 && count > Max_Nick_Length));
}

static void
sync_reginfo (USERDB * db)
{
    log_message ("sync_reginfo(): sending registration info to peers");
    pass_message_args (NULL, MSG_SERVER_REGINFO,
		       ":%s %s %s %s %s %u 0", Server_Name,
		       db->nick, db->password,
#if EMAIL
		       db->email,
#else
		       "unknown",
#endif
		       Levels[db->level], db->created);
}

/* pass a KILL message back to the server where the login request came from.
 * this is used to sync up when we can't parse the login message, so we
 * have no choice but to kill the client.  note that this only gets passed
 * back to the server the request came from.
 */
static void
kill_client (CONNECTION * con, const char *user, const char *reason)
{
    send_cmd (con, MSG_CLIENT_KILL, ":%s %s \"%s\"", Server_Name, user,
	      reason);
    notify_mods (KILLLOG_MODE, "Server %s killed %s: %s", Server_Name, user,
		 reason);
}

static void
zap_local_user (CONNECTION * con, const char *reason)
{
    ASSERT (validate_connection (con));
    ASSERT (ISUSER (con));
    ASSERT (reason != NULL);

    /* TODO: there is a numeric for this somewhere */
    send_cmd (con, MSG_SERVER_NOSUCH, "You were killed by server %s: %s",
	      Server_Name, reason);
    send_cmd (con, MSG_SERVER_DISCONNECTING, "0");
    con->killed = 1;		/* dont generate a QUIT message */
    remove_user (con);
    /* avoid free'g con->user in remove_connection().  do
       this here to avoid the ASSERT() in remove_user() */
    con->class = CLASS_UNKNOWN;
    con->uopt = 0;		/* just to be safe since it was free'd */
    con->user = 0;
    destroy_connection (con);
}

#ifndef ROUTING_ONLY
/* if the server is full, try to find the client connected to the server
 * the longest that isn't sharing any files.  expell that client to make
 * room for other (possibly sharing) clients.
 */
static int
eject_client (CONNECTION * con)
{
    int     i, loser = -1, leech = 0, shared = 0x7fffffff;
    time_t  when = global.current_time;

    for (i = 0; i < global.clients_num; i++)
    {
	if (ISUSER (global.clients[i]) && global.clients[i] != con &&
		!global.clients[i]->killed && /* skip already killed clients */
		/* allow a client time to start sharing files */
		(global.clients[i]->user->connected + EjectAfter < global.current_time) &&
	    (global.clients[i]->user->level == LEVEL_LEECH ||
	     (global.clients[i]->user->level == LEVEL_USER &&
	      global.clients[i]->user->sharing <= global.eject_limit)))
	{
	    /* if we already found a leech, don't boot a LEVEL_USER even
	     * if the leech logged in more recently or is sharing files
	     */
	    if(leech && global.clients[i]->user->level > LEVEL_LEECH)
		continue;

	    /* always boot the client with the least files shared.  we skip
	     * this check when we havent' yet found a leech, but the current
	     * user is a leech, so that a leech sharing more files than a
	     * regular user will get selected.
	     */
	    if (leech ||
		    (!leech && global.clients[i]->user->level > LEVEL_LEECH))
	    {
		if (global.clients[i]->user->shared > shared)
		    continue;
	    }

	    if (global.clients[i]->user->connected < when)
	    {
		loser = i;
		when = global.clients[i]->user->connected;
		if (global.clients[i]->user->level == LEVEL_LEECH)
		    leech = 1;
		shared = global.clients[i]->user->shared;
	    }
	}
    }
    if (loser == -1)
	return 0;		/* no client to eject, reject current login */
    /* pass NULL as the CONNECTION so we send the KILL back to the server
     * where this user came from.  this is ok since the KILL is originating
     * here and not being routed.
     */
    kill_user_internal (NULL, global.clients[loser]->user, Server_Name, 0,
			"server full, not sharing enough");
    return 1;			/* ok for current login to proceed despite being full */
}
#endif

/* find the server name in the cache, or add it if it doesn't yet exist.
 * this allows one copy of the server name in memory rather than copying it
 * 1000 times for each user
 */
static char *
find_server (char *s)
{
    LIST   *list;

    for (list = Server_Names; list; list = list->next)
    {
	if (!strcasecmp (s, list->data))
	    return list->data;
    }
    /* not found yet, allocate */
    list = CALLOC (1, sizeof (LIST));
    list->data = STRDUP (s);
    list->next = Server_Names;
    Server_Names = list;
    return list->data;
}

/* 2 <nick> <pass> <port> <client-info> <speed> [email] [build]

   servers append some additional information that they need to share in
   order to link:

   2 <nick> <pass> <port> <client-info> <speed> <email> <ts> <ip> <server> <serverport>

   <ts> is the time at which the client logged in (timestamp)
   <ip> is the client's ip address
   <server> is the server they are connected to
   <port> is the remote port on the server they are connected to */
HANDLER (login)
{
    char   *av[10];
    USER   *user;
    LIST   *list;
    int     ac, speed, port;
    USERDB *db = 0;
    unsigned int ip;
    char   *host, realhost[256];
    hashlist_t *clientinfo;
    ip_info_t *info;

    (void) len;
    ASSERT (validate_connection (con));

    if (ISUSER (con))
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "you are already logged in");
	return;
    }

    ac = split_line (av, FIELDS (av), pkt);

    /* check for the correct number of fields for this message type.  some
       clients send extra fields, so we just check to make sure we have
       enough for what is required in this implementation. */
    if (ISUNKNOWN (con))
    {
	if (ac < 5)
	{
	    log_message ("login: too few parameters (tag=%d)", tag);
	    print_args (ac, av);
	    if (ISUNKNOWN (con))
	    {
		unparsable (con);
		destroy_connection (con);
	    }
	    return;
	}
	host = con->host;
	ip = con->ip;
	Connection_Count++;	/* local client connections */
    }
    else
    {
	ASSERT (ISSERVER (con));
	if (ac < 10)
	{
	    log_message ("login: too few parameters from server %s", con->host);
	    if (ac > 0)
	    {
		/* send a kill back to this server so we stay synched. */
		kill_client (con, av[0], "bad login message from server");

		/* this could be misleading since we haven't yet checked if
		 * this user is already logged in via this or another server.
		 * so it could look like we have killed the existing users.
		 * however, this shouldn't happen very often since no other
		 * OpenNap software exists at the moment.
		 */
	    }
	    return;
	}
	ip = strtoul (av[7], 0, 10);
	strncpy (realhost, my_ntoa (BSWAP32 (ip)), sizeof (realhost));
	realhost[sizeof (realhost) - 1] = 0;
	host = realhost;
    }

    if (tag == MSG_CLIENT_LOGIN_REGISTER && option (ON_RESTRICT_REGISTRATION))
    {
	if (ISUSER (con))
	    send_cmd (con,MSG_SERVER_ERROR, "Automatic registration is disabled, contact server admin");
	return;
    }

    /* find info on this host */
    info = hash_lookup (Clones, (void *) ip);
    if (!info)
    {
	info = CALLOC (1, sizeof (ip_info_t));
	info->ip = ip;
	hash_add (Clones, (void *) ip, info);
    }

    /* check for clients that are either reconnecting too fast */
    if (ISUNKNOWN (con) && Login_Interval > 0 &&
	    (global.current_time - info->last_connect < Login_Interval))
    {
	/* client is reconnecting too fast */
	log_message ("login: %s is reconnecting too fast", my_ntoa (BSWAP32 (ip)));
	send_cmd (con, MSG_SERVER_ERROR, "reconnecting too fast");
	destroy_connection (con);
	return;
    }

    /* update connection timer */
    info->last_connect = global.current_time;
    info->connects++;

    clientinfo = hashlist_add (Client_Versions, av[3], 0);

    if (invalid_nick (av[0]))
    {
	if (ISUNKNOWN (con))
	{
	    send_cmd (con, MSG_SERVER_BAD_NICK, "");
	    destroy_connection (con);
	}
	else
	{
	    ASSERT (ISSERVER (con));
	    kill_client (con, av[0], "invalid nick");
	}
	return;
    }

    /* retrieve registration info (could be NULL) */
    db = hash_lookup (User_Db, av[0]);

#if ROUTING_ONLY
    /* if running as a hub-only, only accept local client logins from
     * admin+ level users.  we never allow anyone else to log in.
     */
    if (ISUNKNOWN (con) && (!db || db->level < LEVEL_ADMIN))
    {
	log_message ("login: rejected login from %s!%s (not admin+)", av[0],
	     con->host);
	destroy_connection (con);
	return;
    }
#endif

    /* bypass restrictions for privileged users */
    if (!db || db->level < LEVEL_MODERATOR)
    {
    	int clone_count;
	/* check for user!ip ban.  */
	if (check_ban (con, av[0], host))
	    return;

	/* check for max clones (global).  use >= for comparison since we 
	 * are not counting the current connection
	 */
	if ((clone_count = check_class (con, info)))
	{
	    log_message ("login: clones detected from %s [%d]",
		    my_ntoa (BSWAP32 (ip)), clone_count);
	    if (ISUNKNOWN (con))
	    {
		send_cmd (con, MSG_SERVER_ERROR,
			  "Exceeded maximum connections");
		notify_mods (BANLOG_MODE, "Clones detected from %s [%d]",
			     my_ntoa (BSWAP32 (ip)), clone_count);
		destroy_connection (con);
	    }
	    else
	    {
		kill_client (con, av[0], "Exceeded maximum connections");
	    }
	    return;
	}

	if (ISUNKNOWN (con))
	{
	    /* enforce maximum local users */
	    if (global.clients_num >= Max_Connections)
	    {
#ifndef ROUTING_ONLY
		/* check if another client can be ejected */
		if (!option (ON_EJECT_WHEN_FULL) || !eject_client (con))
#endif
		{
		    log_message ("login: max_connections (%d) reached",
			 Max_Connections);
		    send_cmd (con, MSG_SERVER_ERROR,
			      "This server is full (%d connections)",
			      Max_Connections);
		    destroy_connection (con);
		    return;
		}
	    }
	}
    }

    speed = atoi (av[4]);
    if (speed < 0 || speed > 10)
    {
	if (ISUNKNOWN (con))
	{
	    send_cmd (con, MSG_SERVER_ERROR, "%s: invalid speed", av[4]);
	    destroy_connection (con);
	    return;
	}
	ASSERT (ISSERVER (con));
	notify_mods (ERROR_MODE,
		     "Invalid speed %d for user %s from server %s", speed,
		     av[0], con->host);
	log_message ("login: invalid speed %d received from server %s", speed,
	     con->host);
	/* set to something sane.  this is only informational so its not
	   a big deal if we are out of synch */
	speed = 0;
    }

    port = atoi (av[2]);
    if (port < 0 || port > 65535)
    {
	if (ISUNKNOWN (con))
	{
	    send_cmd (con, MSG_SERVER_ERROR, "%s: invalid port", av[2]);
	    destroy_connection (con);
	    return;
	}
	ASSERT (ISSERVER (con));
	notify_mods (ERROR_MODE, "Invalid port %d for user %s from server %s",
		     port, av[0], con->host);
	log_message ("login: invalid port %d received from server %s",
	     port, con->host);
	port = 0;
	/* TODO: generate a change port command */
    }

    if (!db && option (ON_REGISTERED_ONLY))
    {
	send_cmd (con, MSG_SERVER_ERROR, "this is a restricted server");
	destroy_connection (con);
	return;
    }

    if (tag == MSG_CLIENT_LOGIN && db == NULL)
    {
	/* the requested nick is not registered.  if we are supposed to
	 * automatically register all new accounts, switch the command type
	 * here to simulate MSG_CLIENT_LOGIN_REGISTER (6).
	 */
	if (option (ON_AUTO_REGISTER))
	    tag = MSG_CLIENT_LOGIN_REGISTER;
    }

    if (tag == MSG_CLIENT_LOGIN_REGISTER)
    {
	/* check to see if the account is already registered */
	if (db)
	{
	    if (ISUNKNOWN (con))
	    {
		/* this could happen if two clients simultaneously connect
		   and register */
		send_cmd (con, MSG_SERVER_ERROR,
			  "Nick registered to another user");
		destroy_connection (con);
	    }
	    else
	    {
		ASSERT (ISSERVER (con));
		/* need to issue a kill and send the registration info
		   we have on this server */
		kill_client (con, av[0], "Nick registered to another user");
		sync_reginfo (db);
	    }
	    return;
	}
	/* else, delay creating db until after we make sure the nick is
	   not currently in use */
    }
    else if (db)
    {
	ASSERT (tag == MSG_CLIENT_LOGIN);
	/* check the user's password */
	if (check_pass (db->password, av[1]))
	{
	    log_message ("login: bad password for %s (%s) from %s",
		 db->nick, Levels[db->level], host);

	    if (ISUNKNOWN (con))
	    {
		send_cmd (con, MSG_SERVER_ERROR, "Invalid Password");
		destroy_connection (con);
	    }
	    else
	    {
		ASSERT (ISSERVER (con));
		/* if another server let this message pass through, that
		   means they probably have an out of date password.  notify
		   our peers of the registration info.  note that it could be
		   _this_ server that is stale, but when the other servers
		   receive this message they will check the creation date and
		   send back any entries which are more current that this one.
		   kind of icky, but its the best we can do */
		kill_client (con, av[0], "Invalid Password");
		sync_reginfo (db);
	    }
	    return;
	}
    }

    /* check to make sure that this user isn't ready logged in. */
    if ((user = hash_lookup (Users, av[0])))
    {
	ASSERT (validate_user (user));

	if (ISUNKNOWN (con))
	{
	    /* check for ghosts.  if another client from the same ip address
	       logs in, kill the older client and proceed normally */
	    #if 0 /// OOO: Commenting out condition to force kill old connections with
	          /// same IP as everyone is connecting through loopback via proxy.
	          /// Just deny new connection.	          
	    if (!option (ON_GHOST_KILL) || user->ip != con->ip)
	    #endif
	    {
		send_cmd (con, MSG_SERVER_ERROR, "%s is already active",
			  user->nick);
		destroy_connection (con);
		return;
	    }

	    /* pass the kill message to all servers */
	    pass_message_args (NULL, MSG_CLIENT_KILL,
		    ":%s %s \"ghost (%s)\"",
		    Server_Name, user->nick, user->server);
	    notify_mods (KILLLOG_MODE, "Server %s killed %s: ghost (%s)",
		    Server_Name, user->nick, user->server);
	    /* remove the old entry */
	    if (ISUSER (user->con))
	    {
		send_cmd (user->con, MSG_SERVER_GHOST, "");
		zap_local_user (user->con,
			"Someone else is logging in as you, disconnecting.");
	    }
	    else
		hash_remove (Users, user->nick);
	}
	else
	{
	    ASSERT (ISSERVER (con));
	    /* check the timestamp to see which client is older.  the last
	     * one to connect gets killed.
	     */
	    if (atoi (av[6]) < user->connected)
	    {
		/* reject the client that was already logged in since has
		   an older timestamp */

		/* the user we see logged in after the same user on another
		   server, so we want to kill the existing user.  we don't
		   pass this back to the server that we received the login
		   from because that will kill the legitimate user */
		pass_message_args (con, MSG_CLIENT_KILL,
				   ":%s %s \"nick collision (%s %s)\"",
				   Server_Name, user->nick, av[8],
				   user->server);
		notify_mods (KILLLOG_MODE,
			     "Server %s killed %s: nick collision (%s %s)",
			     Server_Name, user->nick, av[8], user->server);

		if (ISUSER (user->con))
		    zap_local_user (user->con, "nick collision");
		else
		    hash_remove (Users, user->nick);
		/* proceed with login normally */
	    }
	    else
	    {
		/* the client we already know about is older, reject
		 * this login
		 */
		log_message
		    ("login: nick collision for user %s, rejected login from server %s",
		     user->nick, con->host);
#if 0
		send_cmd (con, MSG_CLIENT_KILL, ":%s %s \"nick collision\"",
			  Server_Name, user->nick);
#endif
		return;
	    }
	}
    }

    if (tag == MSG_CLIENT_LOGIN_REGISTER)
    {
	/* check to make sure the client isn't registering nicknames too
	 * fast.
	 */
	if (Register_Interval > 0 &&
		(global.current_time - info->last_register < Register_Interval))
	{
	    /* client is attempting to register nicks too fast */
	    log_message ("login: %s is registering nicks too fast",
		    my_ntoa (BSWAP32 (ip)));
	    send_cmd (con, MSG_SERVER_ERROR, "reregistering too fast");
	    destroy_connection (con);
	    return;
	}

	/* create the registration entry now */
	ASSERT (db == 0);
#if 0 /// OOO: Disabling registration

	db = CALLOC (1, sizeof (USERDB));
	if (db)
	{
	    db->nick = STRDUP (av[0]);
	    db->password = generate_pass (av[1]);
#if EMAIL
	    if (ac > 5)
		db->email = STRDUP (av[5]);
	    else
	    {
		snprintf (Buf, sizeof (Buf), "anon@%s", Server_Name);
		db->email = STRDUP (Buf);
	    }
#endif
	}
	if (!db || !db->nick || !db->password
#if EMAIL
	    || !db->email
#endif
	    )
	{
	    OUTOFMEMORY ("login");
	    if (con->class == CLASS_UNKNOWN)
		destroy_connection (con);
	    userdb_free (db);
	    return;
	}
	db->level = LEVEL_USER;
	db->created = global.current_time;
	db->lastSeen = global.current_time;
	if (hash_add (User_Db, db->nick, db))
	{
	    log_message ("login: hash_add failed (ignored)");
	    userdb_free (db);
	    db = NULL;
	}
#endif /// OOO

	/* update the timer for registration.  we wait until here so that
	 * attempts to register existing nicks don't count against the client.
	 * this timer is only to prevent a client from successfully
	 * registering nicks too quickly.
	 */
	info->last_register = global.current_time;
    }

    user = CALLOC (1, sizeof (USER));
    if (user)
    {
#if DEBUG
	user->magic = MAGIC_USER;
#endif
	user->nick = STRDUP (av[0]);
	/* if the client version string is too long, truncate it */
	if (Max_Client_String > 0
	    && strlen (av[3]) > (unsigned) Max_Client_String)
	    *(av[3] + Max_Client_String) = 0;
	user->clientinfo = clientinfo->key;
	user->pass = STRDUP (av[1]);
    }
    if (!user || !user->nick || !user->pass)
    {
	OUTOFMEMORY ("login");
	goto failed;
    }
    user->port = port;
    user->speed = speed;
    user->con = con;
    user->level = LEVEL_USER;	/* default */
    user->ip = ip;

    /* if this is a locally connected user, update our information */
    if (ISUNKNOWN (con))
    {
	/* save the ip address of this client */
	user->connected = global.current_time;
	user->local = 1;
	user->conport = con->port;
	user->server = Server_Name;	/* NOTE: this is not malloc'd */
	con->uopt = CALLOC (1, sizeof (USEROPT));
	if (!con->uopt)
	{
	    OUTOFMEMORY ("login");
	    goto failed;
	}
	con->uopt->usermode = /*LOGALL_MODE */ UserMode_int;
	con->user = user;
	con->class = CLASS_USER;
	/* send the login ack */
#if EMAIL
	if (db)
	    send_cmd (con, MSG_SERVER_EMAIL, "%s", db->email);
	else
#endif
	    send_cmd (con, MSG_SERVER_EMAIL, "anon@%s", Server_Name);
	show_motd (con, 0, 0, NULL);
	server_stats (con, 0, 0, NULL);
    }
    else
    {
	ASSERT (ISSERVER (con));
	user->connected = atoi (av[6]);
	user->server = find_server (av[8]);	/* just a ref, not malloc'd */
	user->conport = atoi (av[9]);
    }

    if (hash_add (Users, user->nick, user))
    {
	log_message ("login(): hash_add failed (fatal)");
	goto failed;
    }

    /* keep track of the number of clients from each unique ip address.  we
     * use this to detect clones globally.
     */
    info->users++;

    /* pass this information to our peer servers */
    pass_message_args (con, MSG_CLIENT_LOGIN,
		       "%s %s %s \"%s\" %s %s %u %u %s %hu",
		       user->nick, av[1], av[2], av[3], av[4],
#if EMAIL
		       db ? db->email : "unknown",
#else
		       "unknown",
#endif /* EMAIL */
		       user->connected, user->ip, user->server,
		       user->conport);

    if (db)
    {
	db->lastSeen = global.current_time;

	/* this must come after the email ack or the win client gets confused */
	if (db->level != LEVEL_USER)
	{
	    /* do this before setting the user level so this user is not
	       notified twice */
	    notify_mods (LEVELLOG_MODE,
			 "Server %s set %s's user level to %s (%d)",
			 Server_Name, user->nick, Levels[db->level],
			 db->level);
	    user->level = db->level;
	    if (ISUSER (con))
	    {
		/* notify users of their change in level */
		send_cmd (con, MSG_SERVER_NOSUCH,
			  "Server %s set your user level to %s (%d).",
			  Server_Name, Levels[user->level], user->level);
		if (user->level >= LEVEL_MODERATOR)
		{
		    LIST   *list = CALLOC (1, sizeof (LIST));

		    list->data = con;
		    Mods = list_push (Mods, list);
		}
	    }
	    /* ensure all servers are synched up.  use the timestamp here
	       so that multiple servers all end up with the same value if
	       they differ */
	    pass_message_args (NULL, MSG_CLIENT_SETUSERLEVEL, ":%s %s %s",
			       Server_Name, user->nick, Levels[user->level]);
	}

	if (db->flags & ON_MUZZLED)
	{
	    /* user was muzzled when they quit, remuzzle */
	    user->muzzled = 1;
	    /* this will result in duplicate messages for the same user from
	       each server, but its the only way to guarantee that the user
	       is muzzled upon login */
	    pass_message_args (NULL, MSG_CLIENT_MUZZLE,
			       ":%s %s \"quit while muzzled\"",
			       Server_Name, user->nick);
	    if (ISUSER (con))
		send_cmd (con, MSG_SERVER_NOSUCH,
			  "You have been muzzled by server %s: quit while muzzled",
			  Server_Name);
	    notify_mods (MUZZLELOG_MODE,
			 "Server %s has muzzled %s: quit while muzzled",
			 Server_Name, user->nick);
	}
    }

    /* check the global hotlist to see if there are any users waiting to be
       informed of this user signing on */
    for (list = hashlist_lookup (Hotlist, user->nick); list;
	 list = list->next)
    {
	ASSERT (validate_connection (list->data));
	send_cmd (list->data, MSG_SERVER_USER_SIGNON, "%s %d",
		  user->nick, user->speed);
    }

    return;

  failed:
    /* clean up anything we allocated here */
    if (!ISSERVER (con))
	destroy_connection (con);
    if (user)
    {
	if (user->nick)
	    FREE (user->nick);
	if (user->pass)
	    FREE (user->pass);
	if (user->server)
	    FREE (user->server);
	FREE (user);
    }
}

/* check to see if a nick is already registered */
/* 7 <nick> */
HANDLER (register_nick)
{
    USERDB *db;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    if (con->class != CLASS_UNKNOWN)
    {
	log_message ("register_nick(): command received after registration");
	send_cmd (con, MSG_SERVER_NOSUCH, "You are already logged in.");
	return;
    }
    if ((db = hash_lookup (User_Db, pkt)))
    {
	send_cmd (con, MSG_SERVER_REGISTER_FAIL, "");
	return;
    }
    if (invalid_nick (pkt))
	send_cmd (con, MSG_SERVER_BAD_NICK, "");
    else
	send_cmd (con, MSG_SERVER_REGISTER_OK, "");
}

/* 10114 :<server> <nick> <password> <level> <email> <created> */
HANDLER (reginfo)
{
    char   *server;
    char   *fields[6];
    USERDB *db;
    int     level;
    int     ac = -1;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_SERVER_CLASS ("reginfo");

    if (*pkt != ':')
    {
	log_message ("reginfo: message does not begin with :");
	return;
    }
    pkt++;
    server = next_arg (&pkt);
    if (pkt)
	ac = split_line (fields, sizeof (fields) / sizeof (char *), pkt);

    if (ac < 5)
    {
	log_message ("reginfo: wrong number of fields");
	return;
    }
    /* look up any entry we have for this user */
    db = hash_lookup (User_Db, pkt);
    if (db)
    {
	/* check the timestamp to see if this is more recent than what
	 * we have
	 */
	if (atol (fields[4]) > db->created)
	{
	    /* our record was created first, notify peers */
	    log_message ("reginfo: stale reginfo received from %s", server);
	    sync_reginfo (db);
	    return;
	}
	/* update our record */
	FREE (db->password);
#if EMAIL
	FREE (db->email);
#endif
    }
    else
    {
	if (invalid_nick (fields[0]))
	{
	    log_message ("reginfo: received invalid nickname");
	    return;
	}
	db = CALLOC (1, sizeof (USERDB));
	if (db)
	    db->nick = STRDUP (fields[0]);
	if (!db || !db->nick)
	{
	    OUTOFMEMORY ("reginfo");
	    if (db)
		FREE (db);
	    return;
	}
	hash_add (User_Db, db->nick, db);
    }
    level = get_level (fields[3]);
    if (level == -1)
    {
	log_message ("reginfo: invalid level %s", fields[3]);
	level = LEVEL_USER;	/* reset to something reasonable */
    }

    pass_message_args (con, tag, ":%s %s %s %s %s %s %s",
		       server, fields[0], fields[1], fields[2], Levels[level],
		       fields[4], (ac > 5) ? fields[5] : "0");

    /* this is already the MD5-hashed password, just copy it */
    db->password = STRDUP (fields[1]);
#if EMAIL
    db->email = STRDUP (fields[2]);
#endif
    if (!db->password
#if EMAIL
	|| !db->email
#endif
	)
    {
	OUTOFMEMORY ("reginfo");
	return;
    }
    db->level = level;
    db->created = atol (fields[4]);
}

/* 10200 [ :<sender> ] <user> <pass> <email> [ <level> ]
   admin command to force registration of a nickname */
HANDLER (register_user)
{
    USER   *sender;
    int     ac = -1, level;
    char   *av[4];
    char   *sender_name;
    USERDB *db;

    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user_server (con, tag, &pkt, &sender_name, &sender))
	return;
    if (sender && sender->level < LEVEL_ADMIN)
    {
	permission_denied (con);
	return;
    }
    if (pkt)
	ac = split_line (av, FIELDS (av), pkt);
    if (ac < 3)
    {
	unparsable (con);
	return;
    }
    if (invalid_nick (av[0]))
    {
	invalid_nick_msg (con);
	return;
    }
    /* if the user level was specified do some security checks */
    if (ac > 3)
    {
	level = get_level (av[3]);
	/* check for a valid level */
	if (level == -1)
	{
	    if (ISUSER (con))
		send_cmd (con, MSG_SERVER_NOSUCH, "Invalid level");
	    return;
	}
	/* check that the user has permission to create a user of this level */
	if (sender && sender->level < LEVEL_ELITE && level >= sender->level)
	{
	    permission_denied (con);
	    return;
	}
    }
    else
	level = LEVEL_USER;	/* default */

    /* first check to make sure this user is not already registered */
    if (hash_lookup (User_Db, av[0]))
    {
	if (sender)
	    send_user (sender, MSG_SERVER_NOSUCH,
		       "[%s] %s is already registered", Server_Name, av[0]);
	return;
    }

    /* pass the plain text password here */
    pass_message_args (con, tag, ":%s %s %s %s %s",
		       sender_name, av[0], av[1], av[2], ac > 3 ? av[3] : "");

    db = CALLOC (1, sizeof (USERDB));
    if (!db)
    {
	OUTOFMEMORY ("register_user");
	return;
    }
    db->nick = STRDUP (av[0]);
    db->password = generate_pass (av[1]);
#if EMAIL
    db->email = STRDUP (av[2]);
#endif
    if (!db->nick || !db->password
#if EMAIL
	|| !db->email
#endif
	)
    {
	OUTOFMEMORY ("register_user");
	FREE (db);
	return;
    }
    db->level = level;
    db->created = global.current_time;
    db->lastSeen = global.current_time;
    hash_add (User_Db, db->nick, db);

    notify_mods (CHANGELOG_MODE, "%s registered nickname %s (%s)",
		 sender_name, db->nick, Levels[db->level]);
}

/* 11 <user> <password>
   check password */
HANDLER (check_password)
{
    char   *nick;
    USERDB *db;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    ASSERT (con->class == CLASS_UNKNOWN);
    nick = next_arg (&pkt);
    if (!nick)
    {
	unparsable (con);
	return;
    }
    if (!pkt)
    {
	send_cmd (con, MSG_SERVER_NOSUCH,
		  "check password failed: missing password");
	return;
    }
    db = hash_lookup (User_Db, nick);
    if (db)
    {
	if (!check_pass (db->password, pkt))
	    send_cmd (con, MSG_SERVER_PASS_OK, "");
    }
}

/* stub handler for numerics we just ignore */
HANDLER (ignore_command)
{
    ASSERT (validate_connection (con));
    (void) tag;
    (void) len;
    (void) pkt;
    (void) con;
    /* just ignore this message for now */
#if 0
    log_message ("ignore_command: (client=%s) tag=%d, len=%d, data=%s",
	 ISUSER (con) ? con->user->clientinfo : "(unknown)", tag, len, pkt);
#endif
}

void
ip_info_free (ip_info_t *info)
{
    FREE (info);
}

static void
cleanup_ip_info_cb (ip_info_t *info, void *unused)
{
    (void) unused;
    if (info->users == 0 &&
	    (global.current_time - info->last_connect > Login_Interval) &&
	    (global.current_time - info->last_register > Register_Interval))
	hash_remove (Clones, (void *) info->ip);
}

/* this function is periodically called to remove stale info from the
 * clone table.  if there are no users from this ip logged in and the
 * last connect is older than minimum allowed, we can safely remove the
 * entry from the list
 */
void
cleanup_ip_info (void)
{
    hash_foreach (Clones, (hash_callback_t) cleanup_ip_info_cb, NULL);
    log_message ("cleanup_ip_info: %d addresses in the table", Clones->dbsize);
}
