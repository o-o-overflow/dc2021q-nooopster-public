/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id: config.c,v 1.102 2001/09/22 06:04:26 drscholl Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include "opennap.h"
#include "debug.h"

typedef enum
{
    VAR_TYPE_INT,
    VAR_TYPE_STR,
    VAR_TYPE_BOOL,
    VAR_TYPE_LIST
}
VAR_TYPE;

#define CF_ONCE	1		/* may only be set in config file or command line */
#define CF_HIDDEN 2		/* can't be queried by a client */

struct config
{
    char   *name;
    VAR_TYPE type;
    unsigned long val;
    unsigned long def;		/* default value */
    unsigned int flags;
};

#define UL (unsigned long)

static struct config Vars[] = {
#ifndef ROUTING_ONLY
    {"allow_share", VAR_TYPE_BOOL, ON_ALLOW_SHARE, 1, 0},
    {"eject_after", VAR_TYPE_INT, UL & EjectAfter, 120, 0},
    {"eject_when_full", VAR_TYPE_BOOL, ON_EJECT_WHEN_FULL, 0, 0},
    {"eject_limit", VAR_TYPE_INT, UL & global.eject_limit, 0, 0},
    {"index_ignore_suffix", VAR_TYPE_BOOL, ON_IGNORE_SUFFIX, 1, 0},
    {"index_path_depth", VAR_TYPE_INT, UL & Index_Path_Depth, 2, 0},
    {"file_count_threshold", VAR_TYPE_INT, UL & File_Count_Threshold, 5000,
     0},
    {"max_results", VAR_TYPE_INT, UL & Max_Search_Results, 100, 0},
    {"max_searches", VAR_TYPE_INT, UL & Max_Searches, 3, 0},
    {"max_shared", VAR_TYPE_INT, UL & Max_Shared, 5000, 0},
    {"report_name", VAR_TYPE_STR, UL & global.report_name, 0, 0},
    {"report_ip", VAR_TYPE_STR, UL & global.report_ip, 0, 0},
    {"report_port", VAR_TYPE_INT, UL & global.report_port, 0, 0},
    {"stat_server_host", VAR_TYPE_STR, UL & global.stat_server,
     UL "stats.napigator.com", 0},
    {"stat_server_pass", VAR_TYPE_STR, UL & global.stat_pass, UL "", CF_HIDDEN},
    {"stat_server_port", VAR_TYPE_INT, UL & global.stat_server_port, 8890, 0},
    {"stat_server_user", VAR_TYPE_STR, UL & global.stat_user, UL "", CF_HIDDEN},
    {"stats_port", VAR_TYPE_INT, UL & Stats_Port, 8889, CF_ONCE},
#endif
    {"auto_link", VAR_TYPE_BOOL, ON_AUTO_LINK, 0, 0},
    {"auto_register", VAR_TYPE_BOOL, ON_AUTO_REGISTER, 0, 0},
    {"client_queue_length", VAR_TYPE_INT, UL & Client_Queue_Length, 102400,
     0},
    {"compression_level", VAR_TYPE_INT, UL & Compression_Level, 1, CF_ONCE},
    {"flood_commands", VAR_TYPE_INT, UL & Flood_Commands, 0, 0},
    {"flood_time", VAR_TYPE_INT, UL & Flood_Time, 0, 0},
    {"ghost_kill", VAR_TYPE_BOOL, ON_GHOST_KILL, 1, 0},
    {"irc_channels", VAR_TYPE_BOOL, ON_IRC_CHANNELS, 1, 0},
    {"listen_addr", VAR_TYPE_STR, UL & Listen_Addr, UL "0.0.0.0", CF_ONCE},
    {"log_mode", VAR_TYPE_BOOL, ON_LOGLEVEL_CHANGE, 0, 0},
    {"login_interval", VAR_TYPE_INT, UL & Login_Interval, 0, 0},
    {"login_timeout", VAR_TYPE_INT, UL & Login_Timeout, 60, 0},
    {"max_browse_result", VAR_TYPE_INT, UL & Max_Browse_Result, 500, 0},
    {"max_channel_length", VAR_TYPE_INT, UL & Max_Channel_Length, 32, 0},
    {"max_client_string", VAR_TYPE_INT, UL & Max_Client_String, 32, 0},
    {"max_clones", VAR_TYPE_INT, UL & Max_Clones, 0, 0},
    {"max_command_length", VAR_TYPE_INT, UL & Max_Command_Length, 2048, 0},
    {"max_connections", VAR_TYPE_INT, UL & Max_Connections, FD_SETSIZE, 0},
    {"max_hotlist", VAR_TYPE_INT, UL & Max_Hotlist, 32, 0},
    {"max_ignore", VAR_TYPE_INT, UL & Max_Ignore, 32, 0},
    {"max_nick_length", VAR_TYPE_INT, UL & Max_Nick_Length, 19, 0},
    {"max_reason", VAR_TYPE_INT, UL & Max_Reason, 64, 0},
    {"max_time_delta", VAR_TYPE_INT, UL & Max_Time_Delta, 90, 0},
    {"max_topic", VAR_TYPE_INT, UL & Max_Topic, 64, 0},
    {"max_user_channels", VAR_TYPE_INT, UL & Max_User_Channels, 5, 0},
    {"min_read", VAR_TYPE_INT, UL & global.min_read, 0, 0},
    {"nick_expire", VAR_TYPE_INT, UL & Nick_Expire, 2678400 /* 31 days */ ,
     0},
    {"ping_interval", VAR_TYPE_INT, UL & Ping_Interval, 600, 0},
    {"register_interval", VAR_TYPE_INT, UL & Register_Interval, 0, 0},
    {"registered_only", VAR_TYPE_BOOL, ON_REGISTERED_ONLY, 0, 0},
    {"restrict_registration", VAR_TYPE_BOOL, ON_RESTRICT_REGISTRATION, 0, 0},
    {"remote_browse", VAR_TYPE_BOOL, ON_REMOTE_BROWSE, 1, 0},
    {"remote_config", VAR_TYPE_BOOL, ON_REMOTE_CONFIG, 1, 0},
    {"search_timeout", VAR_TYPE_INT, UL & Search_Timeout, 180, 0},
    {"server_alias", VAR_TYPE_STR, UL & Server_Alias, 0, CF_ONCE},
    {"server_chunk", VAR_TYPE_INT, UL & Server_Chunk, 0, 0},
    {"server_name", VAR_TYPE_STR, UL & Server_Name, 0, CF_ONCE},
    {"server_ports", VAR_TYPE_LIST, UL & Server_Ports, UL "8888", CF_ONCE},
    {"server_queue_length", VAR_TYPE_INT, UL & Server_Queue_Length, 1048576,
     0},
    {"stat_click", VAR_TYPE_INT, UL & global.stat_click, 60, 0},
    {"strict_channels", VAR_TYPE_BOOL, ON_STRICT_CHANNELS, 0, 0},
    {"user_db_interval", VAR_TYPE_INT, UL & User_Db_Interval, 1800, 0},
    {"usermode", VAR_TYPE_STR, UL & UserMode, UL "ALL", CF_ONCE},
    {"warn_time_delta", VAR_TYPE_INT, UL & Warn_Time_Delta, 30, 0},
    {"who_was_time", VAR_TYPE_INT, UL & Who_Was_Time, 300, 0},
#ifndef WIN32
    {"connection_hard_limit", VAR_TYPE_INT, UL & Connection_Hard_Limit,
     FD_SETSIZE, CF_ONCE},
    {"max_data_size", VAR_TYPE_INT, UL & Max_Data_Size, -1, CF_ONCE},
    {"max_rss_size", VAR_TYPE_INT, UL & Max_Rss_Size, -1, CF_ONCE},
    {"lock_memory", VAR_TYPE_BOOL, ON_LOCK_MEMORY, 0, CF_ONCE},
#endif
};

static int Vars_Size = sizeof (Vars) / sizeof (struct config);

static void
set_int_var (struct config *v, int val)
{
    ASSERT (v->type == VAR_TYPE_INT);
    *(int *) v->val = val;
}

static void
set_str_var (struct config *v, const char *s)
{
    char  **ptr;

    ASSERT (v->type == VAR_TYPE_STR);
    ptr = (char **) v->val;
    if (*ptr)
	FREE (*ptr);
    *ptr = STRDUP (s);
}

static void
set_list_var (struct config *v, const char *s)
{
    int     ac, i;
    char   *av[32];
    LIST   *tmpList, *list = 0;


    ASSERT (v->type == VAR_TYPE_LIST);
    strncpy (Buf, s, sizeof (Buf) - 1);
    Buf[sizeof (Buf) - 1] = 0;
    ac = split_line (av, FIELDS (av), Buf);
    for (i = 0; i < ac; i++)
    {
	tmpList = CALLOC (1, sizeof (LIST));
	tmpList->data = STRDUP (av[i]);
	tmpList->next = list;
	list = tmpList;
    }
    list_free (*(LIST **) v->val, free_pointer);
    *(LIST **) v->val = list;
}

static void
set_bool_var (struct config *v, int on)
{
    ASSERT (v->type == VAR_TYPE_BOOL);
    if (on)
	Server_Flags |= v->val;
    else
	Server_Flags &= ~v->val;
}

static int
set_var (const char *var, const char *val, int init)
{
    int     i, n;
    char   *ptr;

    for (i = 0; i < Vars_Size; i++)
    {
	if (!strcmp (Vars[i].name, var))
	{
	    if (!init && (Vars[i].flags & CF_ONCE))
	    {
		log_message ("set_var: %s may not be reset/only set in the config file", Vars[i].name);
		return -1;
	    }
	    if (Vars[i].type == VAR_TYPE_INT)
	    {
		n = strtol (val, &ptr, 10);
		if (*ptr)
		{
		    log_message ("set_var: invalid integer value: %s", val);
		    return -1;
		}
		set_int_var (&Vars[i], n);
	    }
	    else if (Vars[i].type == VAR_TYPE_STR)
		set_str_var (&Vars[i], val);
	    else if (Vars[i].type == VAR_TYPE_BOOL)
	    {
		if (!strcasecmp ("yes", val) || !strcasecmp ("on", val))
		    n = 1;
		else if (!strcasecmp ("no", val) || !strcasecmp ("off", val))
		    n = 0;
		else
		{
		    n = strtol (val, &ptr, 10);
		    if (*ptr)
		    {
			log_message ("set_var: invalid boolean value: %s", val);
			return -1;
		    }
		}
		set_bool_var (&Vars[i], n);
	    }
	    else if (Vars[i].type == VAR_TYPE_LIST)
		set_list_var (&Vars[i], val);
	    else
	    {
		ASSERT (0);
	    }
	    return 0;
	}
    }
    log_message ("set_var: unknown variable %s", var);
    return -1;
}

static char *
get_str_var (char *name)
{
    int     ac;

    for (ac = 0; ac < Vars_Size; ac++)
    {
	if (!strcasecmp (name, Vars[ac].name)
	    && Vars[ac].type == VAR_TYPE_STR)
	    return *(char **) Vars[ac].val;
    }
    return NULL;
}

int
config (int init)
{
    FILE   *f;
    char   *ptr, *var;
    int     len, line = 0;
    char    path[_POSIX_PATH_MAX];
    char    buf[1024];

    snprintf (path, sizeof (path), "%s/config", Config_Dir);

    if ((f = fopen (path, "r")))
    {
	log_message ("config: reading %s", path);
	buf[sizeof buf - 1] = 0;
	while (fgets (buf, sizeof (buf) - 1, f))
	{
	    line++;
	    ptr = buf;
	    while (isspace (*ptr))
		ptr++;
	    if (!*ptr || *ptr == '#')
		continue;
	    len = strlen (ptr);
	    while (len > 0 && isspace (*(ptr + len - 1)))
		len--;
	    *(ptr + len) = 0;

	    var = next_arg (&ptr);
	    if (!ptr)
	    {
		log_message ("config: error in %s:%d: missing value", path, line);
		continue;
	    }
	    if (set_var (var, ptr, init) != 0)
		log_message ("config: error in %s, line %d", path, line);
	}
	fclose (f);
    }
    else if (errno != ENOENT)
    {
	logerr ("config", path);
	return -1;
    }
    if (init)
	config_user_level (get_str_var ("usermode"));
    return 0;
}

static void
query_var (CONNECTION * con, struct config *v)
{
    if (v->type == VAR_TYPE_INT)
	send_cmd (con, MSG_SERVER_NOSUCH, "%s = %d", v->name,
		  *(int *) v->val);
    else if (v->type == VAR_TYPE_BOOL)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "%s = %s", v->name,
		  (Server_Flags & v->val) ? "on" : "off");
    }
    else if (v->type == VAR_TYPE_LIST)
    {
	char    buf[1024];
	LIST   *tmpList = 0;

	buf[0] = 0;
	for (tmpList = *(LIST **) v->val; tmpList; tmpList = tmpList->next)
	    snprintf (buf + strlen (buf), sizeof (buf) - strlen (buf),
		      "%s ", (char *) tmpList->data);
	send_cmd (con, MSG_SERVER_NOSUCH, "%s = %s", v->name, buf);
    }
    else
    {
	ASSERT (v->type == VAR_TYPE_STR);
	send_cmd (con, MSG_SERVER_NOSUCH, "%s = %s", v->name,
		  *(char **) v->val);
    }
}

/* 810 [ <var> [ <value> ] ] */
HANDLER (server_config)
{
    char   *av[2];
    int     ac;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    /* only local users should be able to config the server.  this is still
     * problematic as currently user levels are shared across all servers
     * meaning an Elite from another server could still log in and alter the
     * settings.
     */
    CHECK_USER_CLASS ("server_config");

    if (!option (ON_REMOTE_CONFIG))
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "remote configuration is disabled");
	return;
    }
    /* allow mods+ to query the config values, only elites can set them */
    if (con->user->level < LEVEL_MODERATOR)
    {
	permission_denied (con);
	return;
    }

    ac = split_line (av, FIELDS (av), pkt);
    if (ac == 0)
    {
	/* user requests all config variables */
	for (ac = 0; ac < Vars_Size; ac++)
	{
	    if (!(Vars[ac].flags & CF_HIDDEN))
		query_var (con, &Vars[ac]);
	}
    }
    else if (ac == 1)
    {
	/* user requests the value of a specific variable */
	for (ac = 0; ac < Vars_Size; ac++)
	    if (!strcasecmp (av[0], Vars[ac].name))
	    {
		if (Vars[ac].flags & CF_HIDDEN)
		    break;	/* hide this variable */
		query_var (con, &Vars[ac]);
		return;
	    }
	send_cmd (con, MSG_SERVER_NOSUCH, "no such variable %s", pkt);
    }
    else
    {
	if (con->user->level < LEVEL_ELITE)
	{
	    permission_denied (con);
	    return;
	}
	/* user changes the value of a specific variable */
	if (set_var (av[0], av[1], 0) != 0)
	{
	    send_cmd (con, MSG_SERVER_NOSUCH, "error setting variable %s",
		      av[0]);
	}
	else
	    notify_mods (CHANGELOG_MODE, "%s set %s to %s",
			 con->user->nick, av[0], av[1]);
    }
}

void
free_config (void)
{
    int     i;

    for (i = 0; i < Vars_Size; i++)
	if (Vars[i].type == VAR_TYPE_STR && *(char **) Vars[i].val)
	    FREE (*(char **) Vars[i].val);
	else if (Vars[i].type == VAR_TYPE_LIST)
	    list_free (*(LIST **) Vars[i].val, free_pointer);
}

/* load the default settings of the server */
void
config_defaults (void)
{
    int     i;

    for (i = 0; i < Vars_Size; i++)
    {
	if (Vars[i].def)
	{
	    if (Vars[i].type == VAR_TYPE_STR)
		set_str_var (&Vars[i], (char *) Vars[i].def);
	    else if (Vars[i].type == VAR_TYPE_INT)
		set_int_var (&Vars[i], Vars[i].def);
	    else if (Vars[i].type == VAR_TYPE_LIST)
		set_list_var (&Vars[i], (char *) Vars[i].def);
	    else if (Vars[i].type == VAR_TYPE_BOOL)
		set_bool_var (&Vars[i], Vars[i].def);
#if DEBUG
	    else
		ASSERT (0);
#endif
	}
    }
}

/* 800 [ :<user> ] <var>
   reset `var' to its default value */
HANDLER (server_reconfig)
{
    int     i;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("server_reconfig");
    ASSERT (validate_user (con->user));
    if (con->user->level < LEVEL_ELITE)
    {
	permission_denied (con);
	return;
    }
    if (!option (ON_REMOTE_CONFIG))
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "remote configuration is disabled");
	return;
    }

    for (i = 0; i < Vars_Size; i++)
	if (!strcmp (pkt, Vars[i].name))
	{
	    if (!(Vars[i].flags & CF_ONCE))
	    {
		send_cmd (con, MSG_SERVER_NOSUCH,
			  "reconfig failed: %s may not be changed",
			  Vars[i].name);
	    }
	    else if (Vars[i].def)
	    {
		if (Vars[i].type == VAR_TYPE_STR)
		    set_str_var (&Vars[i], (char *) Vars[i].def);
		else if (Vars[i].type == VAR_TYPE_INT)
		    set_int_var (&Vars[i], Vars[i].def);
		else if (Vars[i].type == VAR_TYPE_BOOL)
		    set_bool_var (&Vars[i], Vars[i].def);
		else if (Vars[i].type == VAR_TYPE_BOOL)
		    set_list_var (&Vars[i], (char *) Vars[i].def);
		notify_mods (CHANGELOG_MODE, "%s reset %s",
			     con->user->nick, Vars[i].name);
	    }
	    else
	    {
		send_cmd (con, MSG_SERVER_NOSUCH, "no default value for %s",
			  pkt);
	    }
	    return;
	}
    send_cmd (con, MSG_SERVER_NOSUCH, "no such variable %s", pkt);
}

static void
nick_check (server_auth_t * auth, void *unused)
{
    USER   *user;
    USERDB *userdb;

    (void) unused;
    if (auth->alias)
    {
	user = hash_lookup (Users, auth->alias);
	if (user)
	{
	    kill_user_internal (0, user, Server_Name, 0,
				"you may not use this nickname");
	}
	/* if the nick is registered, drop it now */
	userdb = hash_lookup (User_Db, auth->alias);
	if (userdb)
	{
	    log_message ("nick_check: nuking account %s", userdb->nick);
	    hash_remove (User_Db, userdb->nick);
	}
    }
}

void
reload_config (void)
{
    log_message ("reload_config: reloading configuration files");
    config (0);
    /* since the motd is stored in memory, reread it */
    motd_close ();
    motd_init ();
#ifndef ROUTING_ONLY
    /* reread filter file */
    load_filter ();
    load_block ();
#endif
    load_server_auth ();

    /* since the servers file may have changed, ensure that there is
     * no nickname that matches an alias for a server.
     */
    list_foreach (Server_Auth, (list_callback_t) nick_check, 0);
}

/* 10116 [ :user ] [server]
 * reload configuration file
 */
HANDLER (rehash)
{
    USER   *sender;

    (void) len;
    if (pop_user (con, &pkt, &sender))
	return;
    if (sender->level < LEVEL_ELITE)
    {
	permission_denied (con);
	return;
    }
    notify_mods (SERVERLOG_MODE, "%s reloaded configuration on %s",
		 sender->nick, pkt && *pkt ? pkt : Server_Name);
    if (!pkt || !*pkt || !strcasecmp (Server_Name, pkt))
	reload_config ();

    /* pass the message even if this is the server we are reloading so that
     * everyone sees the message
     */
    pass_message_args (con, tag, ":%s %s", sender->nick,
		       pkt && *pkt ? pkt : Server_Name);
}
