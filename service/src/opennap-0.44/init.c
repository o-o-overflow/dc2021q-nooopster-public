/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id: init.c,v 1.68 2001/09/23 23:09:04 drscholl Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef WIN32
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/types.h>
#include <netdb.h>
#include <limits.h>
#endif /* !WIN32 */
#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#ifndef WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#ifdef __EMX__
#include <stdlib.h>
#define _POSIX_PATH_MAX _MAX_PATH
#endif /* __EMX__ */
#include "opennap.h"
#include "hashlist.h"
#include "debug.h"
#if HAVE_MLOCKALL
#include <sys/mman.h>
#endif /* HAVE_MLOCKALL */

static void
lookup_hostname (void)
{
    struct hostent *he;

    /* get our canonical host name */
    gethostname (Buf, sizeof (Buf));
    he = gethostbyname (Buf);
    if (he)
	Server_Name = STRDUP (he->h_name);
    else
    {
	log_message ("lookup_hostname: unable to find fqdn for %s", Buf);
	Server_Name = STRDUP (Buf);
    }
}

#if !defined( WIN32) || defined(__CYGWIN__)
static void
sighandler (int sig)
{
    log_message ("sighandler: caught signal %d", sig);
    switch (sig)
    {
    case SIGHUP:
	reload_config ();
	break;
    case SIGINT:
    case SIGTERM:
	SigCaught = 1;
	break;
    case SIGUSR1:
	CLEANUP ();
	break;
    }
}

#if defined(PARANOID) && defined(DEBUG)
static void
wipe_user_pass (USER * user, void *unused)
{
    (void) unused;
    memset (user->pass, 0, strlen (user->pass));
}

static void
wipe_server_pass (server_auth_t * auth)
{
    memset (auth->their_pass, 0, strlen (auth->their_pass));
    memset (auth->my_pass, 0, strlen (auth->my_pass));
}

static void
handle_sigsegv (int sig)
{
    struct sigaction sa;

    memset (&sa, 0, sizeof (sa));
    sa.sa_handler = SIG_DFL;
    sigaction (SIGSEGV, &sa, 0);	/* set back to default */

    /* every C primer says not to do this, but it seems to work... =) */
    fprintf (stderr, "handle_sigsegv: caught sigsegv, wiping passwords\n");
    fflush (stderr);

    (void) sig;
    /* wipe the user/server passwords before dumping core */
    hash_foreach (User_Db, (hash_callback_t) wipe_user_pass, 0);
    list_foreach (Server_Auth, (list_callback_t) wipe_server_pass, 0);

    kill (getpid (), SIGSEGV);	/* raise the signal again so we get a core */
}
#endif /* PARANOID */

static int
drop_privs (void)
{
    int     n;
    char   *p;
    struct passwd *pw;
    struct group *gr;

    n = strtol (USE_GID, &p, 10);
    if (p)
    {
	/* probably a string */
	gr = getgrnam (USE_GID);
	if (!gr)
	{
	    log_message ("drop_privs: unable to find gid for group %s", USE_GID);
	    return -1;
	}
	n = gr->gr_gid;
    }
    if (setgid (n))
    {
	logerr ("drop_privs", "setgid");
	return -1;
    }

    n = strtol (USE_UID, &p, 10);
    if (p)
    {
	/* probably a string */
	pw = getpwnam (USE_UID);
	if (!pw)
	{
	    log_message ("drop_privs: unable to find uid for user %s", USE_UID);
	    return -1;
	}
	n = pw->pw_uid;
    }
    if (setuid (n))
    {
	logerr ("drop_privs", "setuid");
	return -1;
    }

    return 0;
}
#endif

/* write the pid to a file so an external program can check to see if the
   process is still running. */
static void
dump_pid (void)
{
    FILE   *f;
    char    path[_POSIX_PATH_MAX];

    log_message ("dump_pid: pid is %d", getpid ());
    snprintf (path, sizeof (path), "%s/pid", Config_Dir);
    f = fopen (path, "w");
    if (!f)
    {
	logerr ("dump_pid", path);
	return;
    }
    fprintf (f, "%d\n", (int) getpid ());
    fclose (f);
}

int
init_server (void)
{
#if !defined( WIN32) || defined(__CYGWIN__)
    struct sigaction sa;

    memset (&sa, 0, sizeof (sa));
    sa.sa_handler = sighandler;
    sigaction (SIGHUP, &sa, NULL);
    sigaction (SIGTERM, &sa, NULL);
    sigaction (SIGINT, &sa, NULL);
    sigaction (SIGPIPE, &sa, NULL);
#if !defined( __EMX__) && !defined(__CYGWIN__)
    sa.sa_flags = SA_RESTART;
#endif /* ! __EMX__ */
    sigaction (SIGUSR1, &sa, NULL);
    sigaction (SIGALRM, &sa, NULL);
#ifdef PARANOID
#ifndef DEBUG
    sa.sa_handler = handle_sigsegv;
    sigaction (SIGSEGV, &sa, NULL);
#endif /* DEBUG */
#endif /* PARANOID */
#endif /* !WIN32 */

    log_message ("init_server: version %s starting", VERSION);

    Server_Start = time (&global.current_time);

    /* load default configuration values */
    config_defaults ();

    /* load the config file - note that if CHROOT is defined we are already
     * chrooted when we get here.  we are also running as uid 0 because
     * some of the ulimit's might need to be altered before starting up.
     * so read the config file now, set limits and then drop privs before
     * loading any other files.
     */
    if (config (1))
	return -1;

#if !defined(WIN32) && !defined(__EMX__)
    /* change umask to something more secure */
    umask (077);

    if (set_max_connections (Connection_Hard_Limit))
	return -1;
    if (Max_Data_Size != -1 && set_data_size (Max_Data_Size))
	return -1;
    if (Max_Rss_Size != -1 && set_rss_size (Max_Rss_Size))
	return -1;
#if HAVE_MLOCKALL
    /* prevent swapping by locking all memory into real memory */
    if (option (ON_LOCK_MEMORY) && mlockall (MCL_CURRENT | MCL_FUTURE))
	logerr ("init_server", "mlockall");
#endif /* HAVE_MLOCKALL */

    if (getuid () == 0)
	drop_privs ();
    ASSERT (getuid () != 0);
    ASSERT (getgid () != 0);

    /* log message to show that we really have dropped privs.  if CHROOT
     * was defined, we should also be locked in the jail.  we never need 
     * root privs again and only the config files need to be accessed.
     */
    log_message ("init_server: running as user %d, group %d", getuid (), getgid ());
#endif /* !WIN32 */

#ifndef WIN32
    /* if running in daemon mode, reopen stdout as a log file */
    if (Server_Flags & ON_BACKGROUND)
    {
	char    path[_POSIX_PATH_MAX];
	int     fd;

	snprintf (path, sizeof (path), "%s/log", Config_Dir);
	fd = open (path, O_CREAT | O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR);
	if (fd > 0)
	{
	    /* close stdout */
	    if (dup2 (fd, 1) == -1)
	    {
		logerr ("init_server", "dup2");
		return -1;
	    }
	    close (fd);
	}
	else
	{
	    logerr ("init_server", path);
	    return -1;
	}
    }
#endif

    dump_pid ();

    /* if not defined in the config file, get the system name */
    if (!Server_Name)
	lookup_hostname ();
    log_message ("init_server: my hostname is %s", Server_Name);

    /* read the user database.  we do this even for routing servers so that
     * we keep track of who is allowed to log in.  eventually this should
     * probably just keep track of the few users that are allowed instead of
     * keeping everyone...
     */
    if (userdb_init ())
    {
	log_message ("init_server: userdb_init failed");
	return -1;
    }

    /* initialize hash tables.  the size of the hash table roughly cuts
       the max number of matches required to find any given entry by the same
       factor.  so a 256 entry hash table with 1024 entries will take rougly
       4 comparisons max to find any one entry.  we use prime numbers here
       because that gives the table a little better spread */
    Users = hash_init (1027, (hash_destroy) free_user);
    Channels = hash_init (257, (hash_destroy) free_channel);
    Hotlist = hash_init (521, 0);
    Who_Was = hash_init (1027, (hash_destroy) free_whowas);

    Clones = hash_init (1027, (hash_destroy) ip_info_free);
    hash_set_hash_func (Clones, hash_u_int, hash_compare_u_int);

    /* routing-only servers don't care about any of this crap... */
#ifndef ROUTING_ONLY
    File_Table = hash_init (4001, 0);
    /* set to case-sensitive version.  we always convert to lower case, so
     * we want to speed the comparison up
     */
    hash_set_hash_func (File_Table, hash_string, hash_compare_string);
#if RESUME
    MD5 = hash_init (4001, 0);
#endif
    load_bans ();
    load_block ();
    load_filter ();
    load_channels ();
    acl_init ();
#endif /* !ROUTING_ONLY */
    Client_Versions = hash_init (257, (hash_destroy) hashlist_free);

    init_random ();
    motd_init ();
    load_server_auth ();

    /* figure out what my local ip address is so that when users connect via
     * localhost they can still xfer files.  do this here because
     * server_name can get changed to server_alias below.
     */
    Interface = inet_addr (Listen_Addr);
    if (Interface != INADDR_ANY)
	Server_Ip = Interface;
    else
	Server_Ip = lookup_ip (Server_Name);

#ifndef ROUTING_ONLY
    /* set default values for napigator reporting if they were not
     * explicitly set in the config file
     */
    global.stat_server_fd = -1;
    if (global.report_name == NULL)
	global.report_name = STRDUP (Server_Name);
    if (global.report_ip == NULL)
	global.report_ip = STRDUP (my_ntoa (Server_Ip));
    if (global.report_port == 0)
	global.report_port = atoi (Server_Ports->data);

    if (global.stat_server)
	log_message ("init: napigator reporting set to %s -> %s:%d",
		global.report_name, global.report_ip, global.report_port);
#endif

    if (Server_Alias)
    {
	/* switch to using the alias if its defined.   we delay until here
	 * because we need to find the local servers' ip when clients connect
	 * via localhost.
	 */
	if (Server_Name)
	    FREE (Server_Name);
	Server_Name = STRDUP (Server_Alias);
	log_message ("init_server: using %s as my name", Server_Name);
    }

    return 0;
}
