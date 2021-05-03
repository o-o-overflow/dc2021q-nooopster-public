/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id: main.c,v 1.314 2001/09/30 22:07:07 drscholl Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(WIN32) && !defined(__CYGWIN__)
#include <windows.h>
#include <winsock.h>
#endif /* WIN32 */
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <ctype.h>
#if !defined(WIN32) || defined(__CYGWIN__)
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/time.h>
#endif /* !WIN32 */
#include "opennap.h"
#include "debug.h"

#if DEBUG
#define dprint0(a)	printf(a);
#define dprint1(a,b) printf(a,b);
#else
#define dprint0(a)
#define dprint1(a,b)
#endif

/* offset into global.poll[] for the given file descriptor */
#define POFF(fd)	global.fdmap[fd]

/*
 * Global Variables
 */

global_t global;

LIST   *Bans = 0;		/* bans on ip addresses / users */
LIST   *UserClass = 0;

char    Buf[2048];		/* global scratch buffer */

HASH   *Channel_Db;
int     Client_Queue_Length;
HASH   *Channels = 0;		/* global channel list */
HASH   *Client_Versions;
HASH   *Clones;
int     Compression_Level = 0;
char   *Config_Dir = SHAREDIR;
u_int   Connection_Count = 0;
LIST   *Destroy = 0;
int	EjectAfter;
int     Flood_Commands;
int     Flood_Time;
LIST   *Flooders = 0;
HASH   *Hotlist;		/* global hotlist */
u_int   Interface = INADDR_ANY;
char   *Listen_Addr = 0;
int     Login_Interval;
int     Login_Timeout;
int     Max_Browse_Result;
int     Max_Client_String;
int     Max_Clones;
int     Max_Command_Length;
int     Max_Connections;
int     Max_Hotlist;
int     Max_Ignore;
int     Max_Reason;
int     Max_Search_Results;
int     Max_Searches;
int     Max_Time_Delta;
int     Max_Topic;
int     Max_User_Channels;	/* default, can be changed in config */
LIST   *Mods = 0;		/* local mods+ */
int     Nick_Expire;
double  Num_Gigs = 0;		/* in kB */
int     Num_Files = 0;
int     Ping_Interval;
int     Register_Interval;
int     Search_Timeout;
char   *Server_Alias = 0;
LIST   *Server_Auth = 0;
int     Server_Chunk = 0;
u_int   Server_Ip = 0;
u_int   Server_Flags = 0;
char   *Server_Name = 0;
LIST   *Server_Ports = 0;	/* which port(s) to listen on for connections */
int     Server_Queue_Length;
int     SigCaught = 0;
time_t  Server_Start;		/* time at which the server was started */
int     User_Db_Interval;	/* how often to save the user database */
HASH   *Users;			/* global users list */
int     Warn_Time_Delta;
HASH   *Who_Was;
int     Who_Was_Time = 0;

#ifndef ROUTING_ONLY
int     File_Count_Threshold;
HASH   *File_Table;		/* global file list */
int     Local_Files = 0;	/* number of files shared by local users */
int     Max_Shared;
int     Index_Path_Depth;	/* how many levels including the filename to
				   include when indexing */

#if RESUME
HASH   *MD5;			/* global hash list */
#endif /* RESUME */
int     Stats_Port;		/* port to listen on for stats info */
#endif /* ! ROUTING_ONLY */

#ifndef WIN32
int     Uid;
int     Gid;
int     Connection_Hard_Limit;
int     Max_Data_Size;
int     Max_Rss_Size;
#endif
int     Max_Nick_Length;
int     Max_Channel_Length = 0;

/* local server list.  NOTE that this contains pointers into the global.clients
   list to speed up server-server message passing */
LIST   *Servers = 0;

/* list of all servers in the cluster */
LIST   *Server_Links = 0;

/* Cache of server names for caching the user->server pointers */
LIST   *Server_Names = 0;

void
set_write (int fd)
{
#if HAVE_POLL
    global. poll[POFF (fd)].events |= POLLOUT;
#else
    FD_SET (fd, &global.write_fds);
#endif
}

void
clear_write (int fd)
{
#if HAVE_POLL
    global. poll[POFF (fd)].events &= ~POLLOUT;
#else
    FD_CLR (fd, &global.write_fds);
#endif
}

void
set_read (int fd)
{
#if HAVE_POLL
    global. poll[POFF (fd)].events |= POLLIN;
#else
    FD_SET (fd, &global.read_fds);
#endif
}

void
clear_read (int fd)
{
#if HAVE_POLL
    global. poll[POFF (fd)].events &= ~POLLIN;
#else
    FD_CLR (fd, &global.read_fds);
#endif
}

#define CLICK 64

void
add_fd (int fd)
{
#if HAVE_POLL
    int     off;

    if (global.poll_max == global.poll_num)
    {
	global. poll_max += CLICK;
	global. poll = REALLOC (global.poll,
				sizeof (struct pollfd) * global.poll_max);

	for (off = global.poll_num; off < global.poll_max; off++)
	{
	    global. poll[off].fd = -1;
	    global. poll[off].events = 0;
	    global. poll[off].revents = 0;
	}
    }
#endif

    /* keep track of the biggest fd we've seen */
    if (fd > global.max_fd)
    {
#if HAVE_POLL
	global. fdmap = REALLOC (global.fdmap,
				 sizeof (int) * (fd + 1));

	for (off = global.max_fd + 1; off < fd + 1; off++)
	    global. fdmap[off] = -1;
#endif
	global. max_fd = fd;
    }

#if HAVE_POLL
    off = global.fdmap[fd] = global.poll_num++;

    global. poll[off].fd = fd;
    global. poll[off].events = 0;
    global. poll[off].revents = 0;
#endif
}

#if HAVE_POLL
void
remove_fd (int fd)
{
    if (fd == -1)
    {
	ASSERT (0);
	return;
    }

    if (global.fdmap[fd] == -1)
    {
	ASSERT (0);
	return;
    }

    if (global.fdmap[fd] < global.poll_num - 1)
    {
	/* swap with the last client */
	int     i = global.poll[global.poll_num - 1].fd;

	ASSERT (i != -1);
	ASSERT (global.poll[POFF (fd)].fd == fd);
	ASSERT (global.poll[POFF (i)].fd == i);

	memcpy (&global.poll[POFF (fd)], &global.poll[POFF (i)],
		sizeof (struct pollfd));
	global. fdmap[i] = POFF (fd);
    }

    /* mark as unused */
    global. fdmap[fd] = -1;
    global. poll_num--;

    /* reset the pollfd struct */
    global. poll[global.poll_num].fd = -1;
    global. poll[global.poll_num].events = 0;
    global. poll[global.poll_num].revents = 0;
}
#endif /* HAVE_POLL */

int
add_client (CONNECTION * con, int is_server)
{
    /* allocate more space if required */
    if (global.clients_max == global.clients_num)
    {
	global. clients_max += CLICK;
	global. clients = REALLOC (global.clients,
				   sizeof (CONNECTION *) *
				   global.clients_max);
    }
    con->id = global.clients_num++;
    global. clients[con->id] = con;

    add_fd (con->fd);

    con->class = CLASS_UNKNOWN;
    con->timer = global.current_time;	/* set a login timer */

    set_nonblocking (con->fd);
    set_keepalive (con->fd, 1);	/* enable tcp keepalive messages */

    if (is_server)
    {
	/* we are doing a non-blocking connect, wait for the socket to become
	 * writable
	 */
	con->connecting = 1;
	set_write (con->fd);
    }
    else
    {
	/* user connection, wait for some input */
	set_read (con->fd);
    }
    return 0;
}

void
send_all_clients (int tag, const char *fmt, ...)
{
    va_list ap;
    int     len;
    int     i;

    va_start (ap, fmt);
    vsnprintf (Buf + 4, sizeof (Buf) - 4, fmt, ap);
    va_end (ap);
    len = strlen (Buf + 4);
    set_tag (Buf, tag);
    set_len (Buf, len);
    len += 4;
    for (i = 0; i < global.clients_num; i++)
	if (ISUSER (global.clients[i]))
	            queue_data (global.clients[i], Buf, len);
}

#ifndef ROUTING_ONLY

static void
report_stats (int fd)
{
    int     n;
    struct sockaddr_in sin;
    socklen_t sinsize = sizeof (sin);
    float   loadavg = 0;

    n = accept (fd, (struct sockaddr *) &sin, &sinsize);
    if (n == -1)
    {
	nlogerr ("report_stats", "accept");
	return;
    }
    log_message ("report_stats: connection from %s:%d", inet_ntoa (sin.sin_addr),
	 htons (sin.sin_port));
#ifdef linux
    {
	FILE   *f = fopen ("/proc/loadavg", "r");

	if (f)
	{
	    fscanf (f, "%f", &loadavg);
	    fclose (f);
	}
	else
	{
	    log_message ("report_stats: /proc/loadavg: %s (errno %d)",
		 strerror (errno), errno);
	}
    }
#endif /* linux */
    snprintf (Buf, sizeof (Buf), "%d %d %.2f %.0f 0\n", Users->dbsize,
	      Num_Files, loadavg, Num_Gigs * 1024.);
    WRITE (n, Buf, strlen (Buf));
    CLOSE (n);
}
#endif /* !ROUTING_ONLY */

static void
update_stats (void)
{
    int     numServers = list_count (Servers);
    time_t  delta;

    delta = global.current_time - global.last_click;

    strcpy (Buf, ctime (&Server_Start));
    Buf[strlen (Buf) - 1] = 0;
    log_message ("update_stats: server was started on %s", Buf);
    strcpy (Buf, ctime (&global.current_time));

    Buf[strlen (Buf) - 1] = 0;
    log_message ("update_stats: current time is %s", Buf);
    log_message ("update_stats: library is %d GB, %d files, %d users",
	 (int) (Num_Gigs / 1048576.), Num_Files, Users->dbsize);
    log_message ("update_stats: %d local clients, %d linked servers",
	 global.clients_num - numServers, numServers);

#ifndef ROUTING_ONLY
    log_message ("update_stats: %d local files", Local_Files);
    log_message ("update_stats: File_Table contains %d entries", File_Table->dbsize);
#endif
    if (delta > 0)
	log_message ("update_stats: %d searches/sec", global.search_count / delta);

    log_message ("update_stats: User_Db contains %d entries", User_Db->dbsize);
    log_message ("update_stats: %d channels", Channels->dbsize);
    if (delta > 0)
	log_message ("update_stats: %d kbytes/sec in, %d kbytes/sec out",
	     (int) (global.bytes_in / 1024 / delta),
	     (int) (global.bytes_out / delta / 1024));
    global. total_bytes_in += global.bytes_in;
    global. total_bytes_out += global.bytes_out;
    log_message ("update_stats: %.0f bytes sent, %.0f bytes received",
	 global.total_bytes_out, global.total_bytes_in);

    /* reset counters */
    global. bytes_in = 0;
    global. bytes_out = 0;
    global. search_count = 0;
    global. last_click = global.current_time;

    /* since we send the same data to many people, optimize by forming
       the message once then writing it out */
    send_all_clients (MSG_SERVER_STATS, "%d %d %d", Users->dbsize,
		      Num_Files, (int) (Num_Gigs / 1048576.));

#ifndef ROUTING_ONLY
    /* send live stats to stat server */
    stat_server_push ();
#endif
}

/* accept all pending connections */
static void
accept_connection (int s)
{
    CONNECTION *cli = 0;
    socklen_t sinsize;
    struct sockaddr_in sin;
    int     f;

    for (;;)
    {
	sinsize = sizeof (sin);
#if HAVE_ALARM
	/* set an alarm just in case we end up blocking when a client
	 * disconnects before we get to the accept()
	 */
	alarm (3);
#endif
	if ((f = accept (s, (struct sockaddr *) &sin, &sinsize)) < 0)
	{
#if HAVE_ALARM
	    alarm (0);
#endif
	    if (N_ERRNO != EWOULDBLOCK)
		nlogerr ("accept_connection", "accept");
	    return;
	}
#if HAVE_ALARM
	alarm (0);
#endif

	if (!acl_connection_allowed (BSWAP32 (sin.sin_addr.s_addr)))
	{
	    log_message ("accept_connection: connection from %s denied by ACLs",
		 inet_ntoa (sin.sin_addr));
	    CLOSE (f);
	    continue;
	}

	if ((cli = new_connection ()) == 0)
	    goto error;
	cli->fd = -1;

	/* if we have a local connection, use the external
	   interface so others can download from them */
	if (sin.sin_addr.s_addr == inet_addr ("127.0.0.1"))
	{
	    cli->ip = BSWAP32 (Server_Ip);
	    cli->host = STRDUP (Server_Name);
	}
	else
	{
	    cli->ip = BSWAP32 (sin.sin_addr.s_addr);
	    cli->host = STRDUP (inet_ntoa (sin.sin_addr));
	}
	if (!cli->host)
	{
	    OUTOFMEMORY ("accept_connection");
	    goto error;
	}

	cli->port = ntohs (sin.sin_port);
	cli->fd = f;

	if (add_client (cli, 0 /* not a server */ ))
	    goto error;
    }

    /* not reached */
    ASSERT (0);
    return;
  error:
    if (cli)
    {
	if (cli->fd != -1)
	    CLOSE (cli->fd);
	if (cli->host)
	    FREE (cli->host);
	FREE (cli);
    }
    else
	CLOSE (f);
}

static void
usage (void)
{
    fprintf (stderr,
	     "usage: %s [ -bhrsv ] [ -c DIR ] [ -p PORT ] [ -l IP ]\n",
	     PACKAGE);
    fprintf (stderr, "  -c DIR	read config files from DIR (default: %s)\n",
	     SHAREDIR);
    fputs ("  -b		run as a background process (daemon)\n",
	   stderr);
    fputs ("  -h		print this help message\n", stderr);
    fputs
	("  -l IP		listen only on IP instead of all interfaces\n",
	 stderr);
    fputs ("  -p PORT	listen on PORT for connections (default: 8888)\n",
	   stderr);
    fputs ("  -r		disable remote configuration commands\n", stderr);
    fputs
	("  -s		channels may only be created by privileged users\n",
	 stderr);
    fputs ("  -v		display version information\n", stderr);
    exit (0);
}

static void
version (void)
{
    fprintf (stderr, "%s %s\n", PACKAGE, VERSION);
    fprintf (stderr, "Copyright (C) 2000 drscholl@users.sourceforge.net\n");
    exit (0);
}

#ifdef __CYGWIN__
extern char *optarg;
#endif

static int *
args (int argc, char **argv, int *sockfdcount)
{
    int     i;
    LIST   *ports = 0, *tmpList;
    int     iface = -1;
    int    *sockfd;
    int     not_root = 1;
    int     port;
    int	disable_remote = 0;

#ifndef WIN32
    not_root = (getuid () != 0);
#endif

    while ((i = getopt (argc, argv, "bc:hl:p:rsvD")) != -1)
    {
	switch (i)
	{
	case 'b':
	    Server_Flags |= ON_BACKGROUND;
	    break;
	case 'D':
	    Server_Flags |= ON_NO_LISTEN;	/* dont listen on stats port */
	    break;
	case 'c':
	    /* ignore the command line option if we're running as root.
	     * we don't allow non-root users to specify their own config
	     * files to avoid possible security problems.
	     */
	    if (not_root)
		Config_Dir = optarg;
	    else
	    {
		log_message ("args: can't use -c when run as root");
		exit (1);
	    }
	    break;
	case 'l':
	    iface = inet_addr (optarg);
	    break;
	case 'p':
	    /* don't allow a privileged port to be used from the command line
	     * if running as root.  this can only be specified in the
	     * configuration file defined at compile time.
	     */
	    port = atoi (optarg);
	    if (not_root || port > 1024)
	    {
		tmpList = CALLOC (1, sizeof (LIST));
		tmpList->data = STRDUP (optarg);
		tmpList->next = ports;
		ports = tmpList;
	    }
	    else
	    {
		log_message ("args: privileged ports not allowed on command line");
		exit (1);
	    }
	    break;
	case 'r':
	    disable_remote = 1;
	    break;
	case 's':
	    Server_Flags |= ON_STRICT_CHANNELS;
	    break;
	case 'v':
	    version ();
	    break;
	default:
	    usage ();
	}
    }

#if USE_CHROOT
    /* we always use the compiled directory instead of the one on the command
     * line here to avoid problems.
     */
    if (chroot (SHAREDIR))
    {
	perror ("chroot");
	exit (1);
    }
    if (chdir ("/"))
    {
	perror ("chdir");
	exit (1);
    }
    /* force the config files to be relative to the chroot jail */
    Config_Dir = "/";
    /* privs will be dropped later.  we still need them to read the the
     * config file and set resources.
     */
#endif

#if !defined(WIN32) && !defined(__EMX__)
    /* check whether to run in the background */
    if (Server_Flags & ON_BACKGROUND)
    {
	if (fork () == 0)
	    setsid ();
	else
	    exit (0);
    }
#endif

    if (init_server ())
	exit (1);

    /* if requested, disable remote configuration */
    if (disable_remote)
	    Server_Flags &= ~ON_REMOTE_CONFIG;
    if (!(Server_Flags & ON_REMOTE_CONFIG))
	    log_message("args: remote configuration disabled");

    /* if the interface was specified on the command line, override the
     * value from the config file
     */
    if (iface != -1)
    {
	Interface = iface;
	Server_Ip = iface;
    }

    /* if port(s) were specified on the command line, override the values
       specified in the config file */
    if (!ports)
	ports = Server_Ports;

    /* create the incoming connections socket(s) */
    *sockfdcount = list_count (ports);
    /* ensure at least one valid port */
    if (*sockfdcount < 1)
    {
	log_message ("args: no server ports defined");
	exit (1);
    }
    sockfd = CALLOC (*sockfdcount, sizeof (int));

    log_message ("args: listening on %d sockets", *sockfdcount);
    for (i = 0, tmpList = ports; i < *sockfdcount;
	 i++, tmpList = tmpList->next)
    {
	if ((sockfd[i] = new_tcp_socket (ON_NONBLOCKING | ON_REUSEADDR)) < 0)
	    exit (1);
	if (bind_interface (sockfd[i], Interface, atoi (tmpList->data)) == -1)
	    exit (1);
	if (listen (sockfd[i], SOMAXCONN) < 0)
	{
	    nlogerr ("args", "listen");
	    exit (1);
	}
	log_message ("args: listening on %s port %d", my_ntoa (Interface),
	     atoi (tmpList->data));
	if (sockfd[i] > global.max_fd)
	    global. max_fd = sockfd[i];
    }
    if (ports != Server_Ports)
	list_free (ports, free_pointer);
    return sockfd;
}

/* sync in-memory state to disk so we can restore properly */
static void
dump_state (void)
{
    userdb_dump ();		/* write out the user database */
#ifndef ROUTING_ONLY
    save_bans ();		/* write out server bans */
    dump_channels ();		/* write out persistent channels file */
    acl_save ();		/* save acls */
#endif
}

#ifndef ROUTING_ONLY
static int
init_stats_port (void)
{
    int     sp = -1;

    if (!option (ON_NO_LISTEN) && Stats_Port != -1)
    {
	/* listen on port 8889 for stats reporting */
	if ((sp = new_tcp_socket (ON_REUSEADDR)) == -1)
	    exit (1);
	if (bind_interface (sp, Interface, Stats_Port))
	    exit (1);
	if (listen (sp, SOMAXCONN))
	{
	    logerr ("main", "listen");
	    exit (1);
	}
	if (sp > global.max_fd)
	    global. max_fd = sp;
    }
    return sp;
}
#endif

int     num_reaped = 0;

/* puts the specified connection on the destroy list to be reaped at the
 * end of the main event loop
 */
void
destroy_connection (CONNECTION * con)
{
    LIST   *list;

    ASSERT (validate_connection (con));

    /* already destroyed */
    if (con->fd == -1)
	return;

    dprint1 ("destroy_connection: destroying fd %d\n", con->fd);

    if (con->destroy)
    {
	list = list_find (Destroy, con);
	if (list)
	    return;		/* already destroyed */
	log_message ("destroy_connection: error, destroyed connection not on Destroy list");
	log_message ("destroy_connection: con->host = %s", con->host);
	if (ISUSER (con))
	    log_message ("destroy_connection: con->user->nick = %s", con->user->nick);
    }
    else
	num_reaped++;

    /* append to the list of connections to destroy */
    list = CALLOC (1, sizeof (LIST));
    if (!list)
    {
	OUTOFMEMORY ("destroy_connection");
	return;
    }
    list->data = con;
    ASSERT (list_validate (Destroy));
    Destroy = list_push (Destroy, list);
    ASSERT (Destroy->data == con);
    con->destroy = 1;

    /* we don't want to read/write anything furthur to this fd */
#if HAVE_POLL
    remove_fd (con->fd);
#else
    FD_CLR (con->fd, &global.read_fds);
    FD_CLR (con->fd, &global.write_fds);
#endif /* HAVE_POLL */

    ASSERT (list_count (Destroy) == num_reaped);
}

static void
reap_dead_connection (CONNECTION * con)
{
#if DEBUG
    int     i;
#endif
    ASSERT (validate_connection (con));

#if HAVE_POLL
    ASSERT (global.fdmap[con->fd] == -1);

#if DEBUG
    /* be certain the fd isn't being polled */
    for (i = 0; i < global.poll_num; i++)
	ASSERT (global.poll[i].fd != con->fd);
#endif /* DEBUG */

#else
    /* this should have already happened, but to it here just to be safe */
    FD_CLR (con->fd, &global.read_fds);
    FD_CLR (con->fd, &global.write_fds);
#endif

    if (con->id < global.clients_num - 1)
    {
	/* swap this place with the last connection in the array */
	global. clients[con->id] = global.clients[global.clients_num - 1];
	global. clients[con->id]->id = con->id;
    }
    global. clients_num--;
    global. clients[global.clients_num] = 0;

    /* close either the current descriptor */
    CLOSE (con->fd);

    /* mark that the descriptor has been closed */
    con->fd = -1;

    /* remove from flood list (if present) */
    if (Flooders)
	Flooders = list_delete (Flooders, con);

    /* this call actually free's the memory associated with the connection */
    remove_connection (con);
}

/* we can't use list_free(Destroy, reap_dead_connection) here because
 * reap_dead_connection might try to access `Destroy', which will be pointed
 * to free'd memory.  so this function updates `Destroy' in an atomic
 * fashion such that if `Destroy' is updated, we have the correct new value.
 */
static void
reap_connections (void)
{
    LIST   *tmp;

    while (Destroy)
    {
	tmp = Destroy;
	Destroy = Destroy->next;
	num_reaped--;
	reap_dead_connection (tmp->data);
	FREE (tmp);
    }
    ASSERT (num_reaped == 0);
}

static void
flood_expire (void)
{
    LIST  **list, *tmp;
    CONNECTION *con;

    for (list = &Flooders; *list;)
    {
	con = (*list)->data;
	if (con->flood_start + Flood_Time < global.current_time)
	{
	    /* flood timer expired, resume reading commands */
	    set_read (con->fd);
	    tmp = *list;
	    *list = (*list)->next;
	    FREE (tmp);
	}
	else
	    list = &(*list)->next;
    }
}

/* since server->server data is always queued up so it can be compressed
 * in one shot, we have to explicitly call send_queued_data() for each
 * server here.
 */
static void
flush_server_data (CONNECTION * con, void *unused)
{
    (void) unused;
    ASSERT (validate_connection (con));
    if (send_queued_data (con) == -1)
	destroy_connection (con);
}

#if HAVE_POLL
#define TIMEOUT timeout
#define READABLE(c)	(global.poll[global.fdmap[c]].revents & POLLIN)
#define WRITABLE(c)	(global.poll[global.fdmap[c]].revents & POLLOUT)
#else
#define TIMEOUT to.tv_sec
#define READABLE(c)	FD_ISSET(c,&read_fds)
#define WRITABLE(c)	FD_ISSET(c,&write_fds)
#endif

static void
server_input (CONNECTION * con, void *arg)
{
#if HAVE_POLL
    (void) arg;
    ASSERT (global.fdmap[con->fd] != -1);

    ASSERT ((global.poll[POFF (con->fd)].events & POLLIN) !=0);
    if (global.poll[POFF (con->fd)].revents & POLLIN)
	handle_connection (con);
#else
    fd_set *read_fds = (fd_set *) arg;

    if (FD_ISSET (con->fd, read_fds))
	handle_connection (con);
#endif
}

int
main (int argc, char **argv)
{
    int    *sockfd;		/* server sockets */
    int     sockfdcount;	/* number of server sockets */
    int     i;			/* generic counter */
    int     numfds;

#ifndef ROUTING_ONLY
    int     sp;
#endif
#if HAVE_POLL
    int     timeout;
#else
    struct timeval to;
    fd_set  read_fds, write_fds;
    int selectErrors = 0;
#endif

#if defined(WIN32) && !defined(__CYGWIN__)
    WSADATA wsa;

    WSAStartup (MAKEWORD (1, 1), &wsa);
#endif /* !WIN32 */

    memset (&global, 0, sizeof (global_t));

    /* minimize the stack space for the main loop by moving the command line
       parsing code to a separate routine */
    sockfd = args (argc, argv, &sockfdcount);

#ifndef ROUTING_ONLY
    sp = init_stats_port ();
#endif

#if HAVE_POLL
    global. poll_max = global.max_fd + 1;
    global. poll = CALLOC (global.poll_max, sizeof (struct pollfd));
    for (i = 0; i < global.poll_max; i++)
	global.poll[i].fd = -1;
    global. fdmap =
	CALLOC (global.poll_max, sizeof (int) * (global.max_fd + 1));
    memset (global.fdmap, -1, sizeof (int) * (global.max_fd + 1));
#endif

    for (i = 0; i < sockfdcount; i++)
    {
#if HAVE_POLL
	struct pollfd *p;

	global. fdmap[sockfd[i]] = global.poll_num++;
	p = &global.poll[global.fdmap[sockfd[i]]];

	p->fd = sockfd[i];
	p->events = POLLIN;
#else
	FD_SET (sockfd[i], &global.read_fds);
#endif
    }

#ifndef ROUTING_ONLY
    if (sp != -1)
    {
#if HAVE_POLL
	global. fdmap[sp] = global.poll_num++;
	global. poll[POFF (sp)].fd = sp;
	global. poll[POFF (sp)].events = POLLIN;
#else
	FD_SET (sp, &global.read_fds);
#endif
    }
#endif

    /* schedule periodic events */
    add_timer (global.stat_click, -1, (timer_cb_t) update_stats, 0);

    add_timer (User_Db_Interval, -1, (timer_cb_t) dump_state, 0);
    add_timer (60, -1, (timer_cb_t) expire_bans, 0);
    add_timer (Ping_Interval, -1, (timer_cb_t) lag_detect, 0);
    add_timer (Who_Was_Time, -1, (timer_cb_t) expire_whowas, 0);

    /* initialize so we get the correct delta for the first call to
       update_stats() */
    global. last_click = global.current_time;

    /* auto connect remote servers if requested */
    if (option (ON_AUTO_LINK))
	auto_link ();

    /* main event loop */
    while (!SigCaught)
    {
	global. current_time = time (0);

	TIMEOUT = next_timer ();
	/* if we have a flood list and the timeout is greater than when
	 * the flood expires, reset the timeout
	 */
	if (Flooders && Flood_Time > 0 && TIMEOUT > Flood_Time)
	    TIMEOUT = Flood_Time;

#if HAVE_POLL

#if DEBUG
	/* check to make sure the poll[] array looks kosher */
	for (i = 0; i < global.poll_num; i++)
	{
	    ASSERT (global.poll[i].fd != -1);
	    ASSERT (global.fdmap[global.poll[i].fd] == i);
	}
	for (i = global.poll_num; i < global.poll_max; i++)
	{
	    ASSERT (global.poll[i].fd == -1);
	    ASSERT (global.poll[i].events == 0);
	    ASSERT (global.poll[i].revents == 0);
	}
#endif /* DEBUG */

	numfds = poll (global.poll, global.poll_num, timeout * 1000);

	if (numfds == -1)
	{
	    nlogerr ("main", "poll");
	    continue;
	}
#else
	read_fds = global.read_fds;
	write_fds = global.write_fds;

	to.tv_usec = 0;
	numfds = select (global.max_fd + 1, &read_fds, &write_fds, 0, &to);

	if (numfds == -1)
	{
	    nlogerr ("main", "select");
	    if (++selectErrors == 5)
	    {
		logerr ("main", "too many errors, exiting...");
		break;
	    }
	    continue;
	}

	selectErrors = 0; /* reset */
#endif

	/* pre-read server links */
	list_foreach (Servers, (list_callback_t) server_input,
#ifndef HAVE_POLL
		      &read_fds
#else
		      NULL
#endif
	    );

	/* do client i/o */
	for (i = 0; i < global.clients_num; i++)
	{
#if HAVE_POLL
	    int     off = POFF (global.clients[i]->fd);

	    if (global.poll[off].revents & (POLLNVAL | POLLHUP | POLLERR))
	    {
		if (global.poll[off].revents & POLLERR)
		{
		    int     err;
		    socklen_t errlen = sizeof (err);

		    /* error */
		    if (getsockopt (global.poll[off].fd, SOL_SOCKET,
				    SO_ERROR, &err, &errlen))
			        logerr ("main", "getsockopt");

		    else
		    {
			log_message ("main: fd %d (%s): %s (errno %d)",
			     global.poll[off].fd,
			     global.clients[i]->host, strerror (err), err);
		    }
		}
		else
		    log_message ("main: fd %d %s", global.poll[off].fd,
			 (global.poll[off].
			  revents & POLLNVAL) ? "is invalid" : "got hangup");

		destroy_connection (global.clients[i]);

		continue;
	    }
#endif
	    if (READABLE (global.clients[i]->fd))
	    {
		if (!global.clients[i]->destroy)
		    handle_connection (global.clients[i]);
	    }

	    if (WRITABLE (global.clients[i]->fd))
	    {
		if (global.clients[i]->connecting)
		    complete_connect (global.clients[i]);
		else
		{
#if HAVE_POLL
		    /* sanity check - make sure there was actually data to
		     * write.
		     */
		    if (!ISSERVER (global.clients[i])
			&& !global.clients[i]->sendbuf)
		    {
			log_message ("main: ERROR, fd %d (id %d) was writable with no pending data",
				global.clients[i]->fd, global.clients[i]->id);
			clear_write (global.clients[i]->fd);
		    }
#endif

		    if (send_queued_data (global.clients[i]) == -1)
			        destroy_connection (global.clients[i]);
		}
	    }

	    /* reap connections which have no logged in after
	     * `Login_Timeout' seconds
	     */
	    if (ISUNKNOWN (global.clients[i]) &&
		global.current_time - global.clients[i]->timer >
		Login_Timeout)
	    {
		log_message ("main: terminating %s (login timeout)",
		     global.clients[i]->host);
		send_cmd (global.clients[i], MSG_SERVER_ERROR,
			  "Idle timeout");
		destroy_connection (global.clients[i]);
	    }
	}

	/* handle timed-out remote searches */
	expire_searches ();

#ifndef ROUTING_ONLY
	/* check for stat server i/o */
	if (global.stat_server_fd != -1)
	{
	    if (WRITABLE (global.stat_server_fd))
	    {
		int code;
		socklen_t codesize = sizeof (code);

		clear_write (global.stat_server_fd);
		/* nonblocking connect complete - check connection code */
		if (getsockopt (global.stat_server_fd, SOL_SOCKET, SO_ERROR,
			SOCKOPTCAST &code, &codesize))
		{
		    logerr ("main","getsockopt");
#if HAVE_POLL
		    remove_fd (global.stat_server_fd);
#endif
		    CLOSE (global.stat_server_fd);
		    global.stat_server_fd = -1;
		}
		else if (code)
		{
		    log_message ("main: connection to stat server failed (%s)",
			    strerror (code));
#if HAVE_POLL
		    remove_fd (global.stat_server_fd);
#endif
		    CLOSE (global.stat_server_fd);
		    global.stat_server_fd = -1;
		}
		else
		    set_read (global.stat_server_fd);
	    }
	    else if (READABLE (global.stat_server_fd))
		stat_server_read ();
	}

	/* check for stats port connections */
	if (sp != -1)
	{
#if HAVE_POLL
	    if (global.poll[POFF (sp)].revents & POLLIN)
#else
	    if (FD_ISSET (sp, &read_fds))
#endif /* HAVE_POLL */
		report_stats (sp);
	}
#endif

	/* check for new clients */
	for (i = 0; i < sockfdcount; i++)
	{
#if HAVE_POLL
	    if (global.poll[POFF (sockfd[i])].revents & POLLIN)
#else
	    if (FD_ISSET (sockfd[i], &read_fds))
#endif /* HAVE_POLL */
		accept_connection (sockfd[i]);
	}

	list_foreach (Servers, (list_callback_t) flush_server_data, 0);

	flood_expire ();

	/* execute any pending events now */
	exec_timers (global.current_time);

	/* remove destroyed connections from the client list.  this
	 * MUST be the last operation in the loop since all the previous
	 * can cause connections to be terminated.
	 */
	reap_connections ();
    }

    /* close all open file descriptors properly */
    for (i = 0; i <= global.max_fd; i++)
	CLOSE (i);

    dump_state ();

#if DEBUG

#if HAVE_POLL
    FREE (global.poll);
    FREE (global.fdmap);
#endif
    for (i = 0; i < global.clients_num; i++)
    {
	global. clients[i]->fd = -1;
	remove_connection (global.clients[i]);
    }
    FREE (global.clients);

    FREE (sockfd);

#ifndef ROUTING_ONLY
    free_hash (Filter);
    free_hash (File_Table);
#endif

    free_hash (Users);
    free_hash (Channels);
    Channels = 0;
    free_hash (Hotlist);
    free_hash (User_Db);
    free_hash (Who_Was);
    free_hash (Clones);
    free_hash (Client_Versions);
    free_timers ();

    list_free (Bans, (list_destroy_t) free_ban);
    list_free (Server_Auth, (list_destroy_t) free_server_auth);
    list_free (Server_Names, free_pointer);
    list_free (Destroy, 0);

    /* free up memory associated with global configuration variables */
    free_config ();
    acl_destroy ();

    /* this displays a list of leaked memory.  pay attention to this. */
    CLEANUP ();
#endif

#if defined(WIN32) && !defined(__CYGWIN__)
    WSACleanup ();
#endif

    global. current_time = time (0);
    log_message ("main: server ended at %s", ctime (&global.current_time));

    exit (0);
}
