/* Copyright (C) 2000 edwards@bitchx.dimension6.com
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   Modified by drscholl@users.sourceforge.net 2/25/2000.

   $Id: server_links.c,v 1.30 2001/09/22 05:52:06 drscholl Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#if !defined( WIN32) || defined(__CYGWIN__)
#include <sys/time.h>
#include <unistd.h>
#else
#include <time.h>
#endif
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include "opennap.h"
#include "debug.h"

#if defined( WIN32) && !defined(__CYGWIN__)
/* emulate gettimeofday, only uses seconds since I can't figure out how
 * to get sub-second accurracy
 */
static int
gettimeofday (struct timeval *ptr, void *unused)
{
    memset (ptr, 0, sizeof (struct timeval));

    ptr->tv_sec = time (0);
    return 0;
}
#endif

/* 10112 */
/* process client request for server links */
HANDLER (server_links)
{
    LIST   *list;
    LINK   *slink;
    CONNECTION *serv;

    (void) tag;
    (void) len;
    (void) pkt;
    CHECK_USER_CLASS ("server_links");
    ASSERT (validate_connection (con));

    /* first dump directly connected servers */
    for (list = Servers; list; list = list->next)
    {
	serv = list->data;
	send_cmd (con, MSG_SERVER_LINKS, "%s %hu %s %hu 1",
		  Server_Name, get_local_port (serv->fd), serv->host,
		  serv->port);
    }

    /* dump remote servers */
    for (list = Server_Links; list; list = list->next)
    {
	slink = list->data;
	send_cmd (con, MSG_SERVER_LINKS, "%s %hu %s %hu %d", slink->server,
		  slink->port, slink->peer, slink->peerport, slink->hops);
    }

    /* terminate the list */
    send_cmd (con, MSG_SERVER_LINKS, "");
}

/* 750 [ :<sender> ] <server> [args] */
HANDLER (ping_server)
{
    USER   *sender;
    char   *recip;
    char   *sender_name;

    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user_server (con, tag, &pkt, &sender_name, &sender))
	return;
    recip = next_arg (&pkt);
    if (!recip || !strcasecmp (Server_Name, recip))
    {
	/* local server is being pinged */
	if (ISUSER (con))
	    /* local user issued request */
	    send_cmd (con, tag, "%s %s", Server_Name, NONULL (pkt));
	else
	    /* use inter-server pong message to reply */
	    send_cmd (con, MSG_SERVER_SERVER_PONG,
		      ":%s %s %s", Server_Name, sender_name, NONULL (pkt));
    }
    else if (is_server (recip))
    {
	/* client request from remote server to remote server */
	pass_message_args (con, tag, ":%s %s %s", sender_name, recip,
			   NONULL (pkt));
    }
    else if (ISUSER (con))
	send_cmd (con, MSG_SERVER_NOSUCH,
		  "server ping failed: no such server");
    else
	log_message
	    ("ping_server: recv'd ping for unknown server %s from server %s (originated from %s)",
	     recip, con->host, sender_name);
}

/* 10022 :<server> <recip> [args]
 * server->server pong response
 */
HANDLER (server_pong)
{
    char   *server;
    char   *nick;
    USER   *user;

    CHECK_SERVER_CLASS ("server_pong");

    (void) len;
    server = next_arg (&pkt);
    nick = next_arg (&pkt);
    if (!server || !nick)
    {
	log_message ("server_pong: error, missing argument(s)");
	return;
    }
    server++;			/* skip the colon */

    user = hash_lookup (Users, nick);
    if (user)
    {
	if (ISUSER (user->con))
	    /* user is local, deliver the response */
	    send_cmd (user->con, MSG_CLIENT_PING_SERVER, "%s %s",
		      server, NONULL (pkt));
	else
	    /* route directly to the server that the user is behind */
	    send_cmd (user->con, tag, ":%s %s %s",
		      server, user->nick, NONULL (pkt));
    }
    /* recip is not a user, check to see if it's the local server */
    else if (!strcasecmp (Server_Name, nick))
    {
	char   *secs;
	char   *usecs;

	/* response is for the local server.  do lag checking  */
	secs = next_arg (&pkt);
	usecs = next_arg (&pkt);
	if (secs && usecs)
	{
	    struct timeval tv;

	    gettimeofday (&tv, NULL);

	    notify_mods (PINGLOG_MODE, "Pong from server %s [%d millisecs]",
			 server,
			 (int) ((((tv.tv_sec - atoi (secs)) * 1000000. +
			  tv.tv_usec - atoi (usecs)) / 1000000.) * 1000.));
	}
	else
	    log_message ("server_pong: pong from %s with invalid args", con->host);
    }
    else if (is_server (nick))
	pass_message_args (con, tag, ":%s %s %s", server, nick, NONULL (pkt));
    else
	log_message ("server_pong: unknown target %s from server %s", nick,
	     con->host);
}

/* this currently doesn't do anything more than ping the peer servers and
 * report the lag times to mods+
 */
void
lag_detect (void *p)
{
    LIST   *list;
    CONNECTION *con;
    struct timeval tv;

    (void) p;			/* unused */

    if (Servers)
    {
	gettimeofday (&tv, 0);
	/* ping all of our peer servers */
	for (list = Servers; list; list = list->next)
	{
	    con = list->data;
	    send_cmd (con, MSG_CLIENT_PING_SERVER, ":%s %s %u %u",
		      Server_Name, con->host, tv.tv_sec, tv.tv_usec);
	}
	notify_mods (PINGLOG_MODE, "Pinging all peer servers...");
    }
}

/* 10120
 * ping all peer servers
 */
HANDLER (ping_all_servers)
{
    (void) tag;
    (void) len;
    (void) pkt;
    CHECK_USER_CLASS ("ping_all_servers");
    if (con->user->level < LEVEL_MODERATOR)
    {
	send_cmd (con, MSG_SERVER_NOSUCH,
		  "ping all servers failed: permission denied");
	return;
    }
    lag_detect (0);
}

void
free_server_auth (server_auth_t * auth)
{
    FREE (auth->name);
    if (auth->alias)
	FREE (auth->alias);
    FREE (auth->their_pass);
    FREE (auth->my_pass);
    FREE (auth);
}

void
load_server_auth (void)
{
    char    path[_POSIX_PATH_MAX];
    FILE   *fp;
    int     ac;
    char   *av[10];
    int     line = 0;
    server_auth_t *slink;
    LIST   *list;

    list_free (Server_Auth, (list_destroy_t) free_server_auth);
    Server_Auth = 0;

    snprintf (path, sizeof (path), "%s/servers", Config_Dir);
    fp = fopen (path, "r");
    if (!fp)
    {
	if (errno != ENOENT)
	    logerr ("load_server_auth_info", path);
	return;
    }
    log_message ("load_server_auth_info: reading %s", path);
    Buf[sizeof (Buf) - 1] = 0;
    while (fgets (Buf, sizeof (Buf) - 1, fp))
    {
	line++;
	if (Buf[0] == '#' || isspace (Buf[0]))
	    continue;
	ac = split_line (av, FIELDS (av), Buf);
	if (ac >= 3)
	{
	    slink = CALLOC (1, sizeof (server_auth_t));
	    slink->name = STRDUP (av[0]);
	    slink->their_pass = STRDUP (av[1]);
	    slink->my_pass = STRDUP (av[2]);
	    if (ac >= 4)
	    {
		slink->port = atoi (av[3]);
		if (slink->port < 1 || slink->port > 65535)
		{
		    log_message ("load_server_auth_info: invalid port at line %d",
			 line);
		    slink->port = 8888;
		}
		/* if a nickname for the server is given, save it so that
		 * we can sheild the real dns name from the masses (used
		 * for routing-only servers which we want to make pratically
		 * invisible).
		 */
		if (ac >= 5)
		    slink->alias = STRDUP (av[4]);
	    }
	    else
		slink->port = 8888;
	    list = CALLOC (1, sizeof (LIST));
	    list->data = slink;
	    list->next = Server_Auth;
	    Server_Auth = list;
	}
	else
	    log_message ("load_server_auth_info: too few parameters at line %d",
		 line);
    }

    fclose (fp);
}
