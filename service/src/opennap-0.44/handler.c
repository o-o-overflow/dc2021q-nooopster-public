/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id: handler.c,v 1.114 2001/09/22 05:52:06 drscholl Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include "opennap.h"
#include "debug.h"
#if DEBUG
#include <ctype.h>
#endif

static  HANDLER (histogram);

/* 214 */
HANDLER (server_stats)
{
    (void) pkt;
    (void) len;
    (void) tag;
    send_cmd (con, MSG_SERVER_STATS, "%d %d %d", Users->dbsize, Num_Files,
	      (int) (Num_Gigs / 1048576.));
}

/* 10018 :<server> <target> <packet>
   allows a server to send an arbitrary message to a remote user */
HANDLER (encapsulated)
{
    char   *nick, ch, *ptr;
    USER   *user;

    (void) tag;
    ASSERT (validate_connection (con));
    CHECK_SERVER_CLASS ("encapsulated");
    if (*pkt != ':')
    {
	log_message ("encapsulated: server message does not begin with a colon (:)");
	return;
    }
    nick = strchr (pkt + 1, ' ');
    if (!nick)
    {
	log_message ("encapsulated: missing target nick");
	return;
    }
    nick++;
    ptr = strchr (nick, ' ');
    if (!ptr)
    {
	log_message ("encapsulated: missing encapsulated packet");
	return;
    }
    ch = *ptr;
    *ptr = 0;
    user = hash_lookup (Users, nick);
    if (!user)
    {
	log_message ("encapsulated: no such user %s", nick);
	return;
    }
    if (user->local)
    {
	ptr++;
	queue_data (user->con, ptr, len - (ptr - pkt));
    }
    else
    {
	*ptr = ch;
	/* avoid copying the data twice by peeking into the send buffer to
	   grab the message header and body together */
	pass_message (con, con->recvbuf->data + con->recvbuf->consumed,
		      4 + len);
    }
}

/* the windows napster client will hang indefinitely waiting for this, so
 * return what it expects.
 */
static HANDLER (version_check)
{
    (void) pkt;
    (void) tag;
    (void) len;
    if (ISUSER (con))
	send_cmd (con, MSG_CLIENT_VERSION_CHECK, "");
}

/* certain user commands need to be exempt from flood control or the server
 * won't work correctly.
 */
#define F_EXEMPT		1	/* exempt from flood control */

typedef struct
{
    unsigned int message;
            HANDLER ((*handler));
    unsigned int flags;
    unsigned long count;
    double  bytes;
}
HANDLER;

#define NORMAL(a,b) {a,b,0,0,0}
#define EXEMPT(a,b) {a,b,F_EXEMPT,0,0}

/* this is the table of valid commands we accept from both users and servers
   THIS TABLE MUST BE SORTED BY MESSAGE TYPE */
static HANDLER Protocol[] = {
    NORMAL (MSG_SERVER_ERROR, server_error),	/* 0 */
    NORMAL (MSG_CLIENT_LOGIN, login),	/* 2 */
    NORMAL (MSG_CLIENT_VERSION_CHECK, version_check),	/* 4 */
    NORMAL (MSG_CLIENT_LOGIN_REGISTER, login),	/* 6 */
    NORMAL (MSG_CLIENT_REGISTER, register_nick),	/* 7 */
    NORMAL (MSG_CLIENT_CHECK_PASS, check_password),	/* 11 */
    NORMAL (MSG_CLIENT_REGISTRATION_INFO, ignore_command),	/* 14 */
#ifndef ROUTING_ONLY
    EXEMPT (MSG_CLIENT_ADD_FILE, add_file),	/* 100 */
    EXEMPT (MSG_CLIENT_REMOVE_FILE, remove_file),	/* 102 */
#endif
    NORMAL (MSG_CLIENT_UNSHARE_ALL, unshare_all),	/* 110 */
#ifndef ROUTING_ONLY
    NORMAL (MSG_CLIENT_SEARCH, search),	/* 200 */
#endif
    NORMAL (MSG_CLIENT_DOWNLOAD, download),	/* 203 */
    NORMAL (MSG_CLIENT_PRIVMSG, privmsg),	/* 205 */
    EXEMPT (MSG_CLIENT_ADD_HOTLIST, add_hotlist),	/* 207 */
    EXEMPT (MSG_CLIENT_ADD_HOTLIST_SEQ, add_hotlist),	/* 208 */
    NORMAL (MSG_CLIENT_BROWSE, browse),	/* 211 */
    NORMAL (MSG_SERVER_STATS, server_stats),	/* 214 */
    NORMAL (MSG_CLIENT_RESUME_REQUEST, resume),	/* 215 */
    NORMAL (MSG_CLIENT_DOWNLOAD_START, download_start),	/* 218 */
    NORMAL (MSG_CLIENT_DOWNLOAD_END, download_end),	/* 219 */
    NORMAL (MSG_CLIENT_UPLOAD_START, upload_start),	/* 220 */
    NORMAL (MSG_CLIENT_UPLOAD_END, upload_end),	/* 221 */
    NORMAL (MSG_CLIENT_CHECK_PORT, ignore_command),	/* 300 */
    NORMAL (MSG_CLIENT_REMOVE_HOTLIST, remove_hotlist),	/* 303 */
    NORMAL (MSG_CLIENT_IGNORE_LIST, ignore_list),	/* 320 */
    NORMAL (MSG_CLIENT_IGNORE_USER, ignore),	/* 322 */
    NORMAL (MSG_CLIENT_UNIGNORE_USER, unignore),	/* 323 */
    NORMAL (MSG_CLIENT_CLEAR_IGNORE, clear_ignore),	/* 326 */
    NORMAL (MSG_CLIENT_JOIN, join),	/* 400 */
    NORMAL (MSG_CLIENT_PART, part),	/* 401 */
    NORMAL (MSG_CLIENT_PUBLIC, public),	/* 402 */
    NORMAL (MSG_SERVER_PUBLIC, public),	/* 403 */
    NORMAL (MSG_SERVER_NOSUCH, server_error),	/* 404 */
    NORMAL (MSG_SERVER_TOPIC, topic),	/* 410 */
    NORMAL (MSG_CLIENT_CHANNEL_BAN_LIST, channel_banlist),	/* 420 */
    NORMAL (MSG_CLIENT_CHANNEL_BAN, channel_ban),	/* 422 */
    NORMAL (MSG_CLIENT_CHANNEL_UNBAN, channel_ban),	/* 423 */
    NORMAL (MSG_CLIENT_CHANNEL_CLEAR_BANS, channel_clear_bans),	/* 424 */
    NORMAL (MSG_CLIENT_DOWNLOAD_FIREWALL, download),	/* 500 */
    NORMAL (MSG_CLIENT_USERSPEED, user_speed),	/* 600 */
    NORMAL (MSG_CLIENT_WHOIS, whois),	/* 603 */
    NORMAL (MSG_CLIENT_SETUSERLEVEL, level),	/* 606 */
    NORMAL (MSG_SERVER_UPLOAD_REQUEST, upload_request),	/* 607 */
    NORMAL (MSG_CLIENT_UPLOAD_OK, upload_ok),	/* 608 */
    NORMAL (MSG_CLIENT_KILL, kill_user),	/* 610 */
    NORMAL (MSG_CLIENT_NUKE, nuke),	/* 611 */
    NORMAL (MSG_CLIENT_BAN, ban),	/* 612 */
    NORMAL (MSG_CLIENT_ALTER_PORT, alter_port),	/* 613 */
    NORMAL (MSG_CLIENT_UNBAN, unban),	/* 614 */
    NORMAL (MSG_CLIENT_BANLIST, banlist),	/* 615 */
    NORMAL (MSG_CLIENT_LIST_CHANNELS, list_channels),	/* 618 */
    NORMAL (MSG_CLIENT_LIMIT, queue_limit),	/* 619 */
    NORMAL (MSG_CLIENT_MOTD, show_motd),	/* 621 */
    NORMAL (MSG_CLIENT_MUZZLE, muzzle),	/* 622 */
    NORMAL (MSG_CLIENT_UNMUZZLE, muzzle),	/* 623 */
    NORMAL (MSG_CLIENT_ALTER_SPEED, alter_speed),	/* 625 */
    NORMAL (MSG_CLIENT_DATA_PORT_ERROR, data_port_error),	/* 626 */
    NORMAL (MSG_CLIENT_WALLOP, wallop),	/* 627 */
    NORMAL (MSG_CLIENT_ANNOUNCE, announce),	/* 628 */
    NORMAL (MSG_CLIENT_BROWSE_DIRECT, browse_direct),	/* 640 */
    NORMAL (MSG_SERVER_BROWSE_DIRECT_OK, browse_direct_ok),	/* 641 */
    NORMAL (MSG_CLIENT_CLOAK, cloak),	/* 652 */
    NORMAL (MSG_CLIENT_CHANGE_SPEED, change_speed),	/* 700 */
    NORMAL (MSG_CLIENT_CHANGE_PASS, change_pass),	/* 701 */
    NORMAL (MSG_CLIENT_CHANGE_EMAIL, change_email),	/* 702 */
    NORMAL (MSG_CLIENT_CHANGE_DATA_PORT, change_data_port),	/* 703 */
    NORMAL (MSG_CLIENT_PING_SERVER, ping_server),	/* 750 */
    NORMAL (MSG_CLIENT_PING, ping),	/* 751 */
    NORMAL (MSG_CLIENT_PONG, ping),	/* 752 */
    NORMAL (MSG_CLIENT_ALTER_PASS, alter_pass),	/* 753 */
    NORMAL (MSG_CLIENT_SERVER_RECONFIG, server_reconfig),	/* 800 */
    NORMAL (MSG_CLIENT_SERVER_VERSION, server_version),	/* 801 */
    NORMAL (MSG_CLIENT_SERVER_CONFIG, server_config),	/* 810 */
    NORMAL (MSG_CLIENT_CLEAR_CHANNEL, clear_channel),	/* 820 */
    NORMAL (MSG_CLIENT_REDIRECT, redirect_client),	/* 821 */
    NORMAL (MSG_CLIENT_CYCLE, cycle_client),	/* 822 */
    NORMAL (MSG_CLIENT_SET_CHAN_LEVEL, channel_level),	/* 823 */
    NORMAL (MSG_CLIENT_EMOTE, emote),	/* 824 */
    NORMAL (MSG_CLIENT_CHANNEL_LIMIT, channel_limit),	/* 826 */
    NORMAL (MSG_CLIENT_FULL_CHANNEL_LIST, full_channel_list),	/* 827 */
    NORMAL (MSG_CLIENT_KICK, kick),	/* 829 */
    NORMAL (MSG_CLIENT_NAMES_LIST, list_users),	/* 830 */
    NORMAL (MSG_CLIENT_GLOBAL_USER_LIST, global_user_list),	/* 831 */
#ifndef ROUTING_ONLY
    EXEMPT (MSG_CLIENT_ADD_DIRECTORY, add_directory),	/* 870 */
#endif
    NORMAL (920, ignore_command),	/* 920 */

    /* non-standard messages */
    NORMAL (MSG_CLIENT_QUIT, client_quit),	/* 10000 */
    NORMAL (MSG_SERVER_LOGIN, server_login),	/* 10010 */
    NORMAL (MSG_SERVER_LOGIN_ACK, server_login_ack),	/* 10011 */
    NORMAL (MSG_SERVER_USER_SHARING, user_sharing),	/* 10012 */
    NORMAL (MSG_SERVER_REGINFO, reginfo),	/* 10014 */
    NORMAL (MSG_SERVER_REMOTE_SEARCH, remote_search),	/* 10015 */
    NORMAL (MSG_SERVER_REMOTE_SEARCH_RESULT, remote_search_result),	/* 10016 */
    NORMAL (MSG_SERVER_REMOTE_SEARCH_END, remote_search_end),	/* 10017 */
    NORMAL (MSG_SERVER_ENCAPSULATED, encapsulated),	/* 10018 */
    NORMAL (MSG_SERVER_LINK_INFO, link_info),	/* 10019 */
    NORMAL (MSG_SERVER_QUIT, server_disconnect),	/* 10020 - deprecated by 10101 */
    NORMAL (MSG_SERVER_NOTIFY_MODS, remote_notify_mods),	/* 10021 */
    NORMAL (MSG_SERVER_SERVER_PONG, server_pong),	/* 10022 */
    NORMAL (MSG_SERVER_TIME_CHECK, time_check),	/* 10023 */
    NORMAL (MSG_SERVER_WHOIS_NOTIFY, whois_notify),	/* 10024 */
    NORMAL (MSG_CLIENT_CONNECT, server_connect),	/* 10100 */
    NORMAL (MSG_CLIENT_DISCONNECT, server_disconnect),	/* 10101 */
    NORMAL (MSG_CLIENT_KILL_SERVER, kill_server),	/* 10110 */
    NORMAL (MSG_CLIENT_REMOVE_SERVER, remove_server),	/* 10111 */
    NORMAL (MSG_CLIENT_LINKS, server_links),	/* 10112 */
    NORMAL (MSG_CLIENT_USAGE_STATS, server_usage),	/* 10115 */
    NORMAL (MSG_CLIENT_REHASH, rehash),	/* 10116 */
    NORMAL (MSG_CLIENT_VERSION_STATS, client_version_stats),	/* 10118 */
    NORMAL (MSG_CLIENT_WHICH_SERVER, which_server),	/* 10119 */
    NORMAL (MSG_CLIENT_PING_ALL_SERVERS, ping_all_servers),	/* 10120 */
    NORMAL (MSG_CLIENT_WHO_WAS, who_was),	/* 10121 */
    NORMAL (MSG_CLIENT_MASS_KILL, mass_kill),	/* 10122 */
    NORMAL (MSG_CLIENT_HISTOGRAM, histogram),	/* 10123 */
    NORMAL (MSG_CLIENT_REGISTER_USER, register_user),	/* 10200 */
    NORMAL (MSG_CLIENT_USER_MODE, user_mode_cmd),	/* 10203 */
    NORMAL (MSG_CLIENT_OP, channel_op),	/* 10204 */
    NORMAL (MSG_CLIENT_DEOP, channel_op),	/* 10205 */
    NORMAL (MSG_CLIENT_CHANNEL_WALLOP, channel_wallop),	/* 10208 */
    NORMAL (MSG_CLIENT_CHANNEL_MODE, channel_mode),	/* 10209 */
    NORMAL (MSG_CLIENT_CHANNEL_INVITE, channel_invite),	/* 10210 */
    NORMAL (MSG_CLIENT_CHANNEL_VOICE, channel_op),	/* 10211 */
    NORMAL (MSG_CLIENT_CHANNEL_UNVOICE, channel_op),	/* 10212 */
    NORMAL (MSG_CLIENT_CHANNEL_MUZZLE, channel_muzzle),	/* 10213 */
    NORMAL (MSG_CLIENT_CHANNEL_UNMUZZLE, channel_muzzle),	/* 10214 */
    NORMAL (MSG_CLIENT_CLASS_ADD, generic_acl_add), /* 10250 */
    NORMAL (MSG_CLIENT_CLASS_DEL, generic_acl_del), /* 10251 */
    NORMAL (MSG_CLIENT_CLASS_LIST, generic_acl_list), /* 10252 */
    NORMAL (MSG_CLIENT_DLINE_ADD, generic_acl_add),
    NORMAL (MSG_CLIENT_DLINE_DEL, generic_acl_del),
    NORMAL (MSG_CLIENT_DLINE_LIST, generic_acl_list),
    NORMAL (MSG_CLIENT_ILINE_ADD, generic_acl_add),
    NORMAL (MSG_CLIENT_ILINE_DEL, generic_acl_del),
    NORMAL (MSG_CLIENT_ILINE_LIST, generic_acl_list),
    NORMAL (MSG_CLIENT_ELINE_ADD, generic_acl_add),
    NORMAL (MSG_CLIENT_ELINE_DEL, generic_acl_del),
    NORMAL (MSG_CLIENT_ELINE_LIST, generic_acl_list),

#ifndef ROUTING_ONLY
    EXEMPT (MSG_CLIENT_SHARE_FILE, share_file),	/* 10300 */
#endif
#if 0
    NORMAL (MSG_CLIENT_BROWSE_NEW, browse_new),	/* 10301 */
#endif
};
static int Protocol_Size = sizeof (Protocol) / sizeof (HANDLER);

/* dummy entry used to keep track of invalid commands */
static HANDLER unknown_numeric = { 0, 0, 0, 0, 0 };

/* 10123
 * report statistics for server commands.
 */
static HANDLER (histogram)
{
    unsigned long  count = 0;
    double  bytes = 0;
    int     l;

    (void) pkt;
    (void) len;
    CHECK_USER_CLASS ("histogram");
    if (con->user->level < LEVEL_ELITE)
    {
	permission_denied (con);
	return;
    }
    for (l = 0; l < Protocol_Size; l++)
    {
	send_cmd (con, tag, "%d %u %.0f", Protocol[l].message,
		  Protocol[l].count, Protocol[l].bytes);
	count += Protocol[l].count;
	bytes += Protocol[l].bytes;
    }
    send_cmd (con, MSG_SERVER_HISTOGRAM, "%d %u %.0f %lu %.0f",
	      unknown_numeric.message, unknown_numeric.count,
	      unknown_numeric.bytes, count, bytes);
}

/* use a binary search to find the table in the entry */
static int
find_handler (unsigned int tag)
{
    int     min = 0, max = Protocol_Size - 1, try;

    while (!SigCaught)
    {
	try = (max + min) / 2;
	if (tag == Protocol[try].message)
	    return try;
	else if (min == max)
	    return -1;		/* not found */
	else if (tag < Protocol[try].message)
	{
	    if (try == min)
		return -1;
	    max = try - 1;
	}
	else
	{
	    if (try == max)
		return -1;
	    min = try + 1;
	}
	ASSERT (min <= max);
    }
    return -1;
}

/* this is not a real handler, but takes the same arguments as one */
HANDLER (dispatch_command)
{
    int     l;
    u_char  byte;

    ASSERT (validate_connection (con));
    ASSERT (pkt != 0);

    /* HACK ALERT
       the handler routines all assume that the `pkt' argument is nul (\0)
       terminated, so we have to replace the byte after the last byte in
       this packet with a \0 to make sure we dont read overflow in the
       handlers.  the handle_connection() function should always allocate 1
       byte more than necessary for this purpose */
    ASSERT (VALID_LEN
	    (con->recvbuf->data, con->recvbuf->consumed + 4 + len + 1));
    byte = *(pkt + len);
    *(pkt + len) = 0;
    l = find_handler (tag);
    if (l != -1)
    {
	ASSERT (Protocol[l].handler != 0);

	/* do flood control if enabled */
	if (Flood_Time > 0 && !(Protocol[l].flags & F_EXEMPT) && ISUSER (con))
	{
	    /* this command is subject to flood control. */
	    if (con->flood_start + Flood_Time < global.current_time)
	    {
		/* flood expired, reset counters */
		con->flood_start = global.current_time;
		con->flood_commands = 0;
	    }
	    else if (++con->flood_commands >= Flood_Commands)
	    {
		LIST   *list;

		log_message
		    ("dispatch_command: flooding from %s!%s (numeric = %hu)",
		     con->user->nick, con->host, tag);
		notify_mods (FLOODLOG_MODE,
			     "Flooding from %s!%s (numeric = %hu)",
			     con->user->nick, con->host, tag);
		/* stop reading from the descriptor until the flood counter
		 * expires.
		 */
		clear_read (con->fd);

		/* add to the list of flooders that is check in the main
		 * loop.  Since we don't traverse the entire client list we
		 * have to keep track of which ones to check for expiration
		 */
		list = CALLOC (1, sizeof (LIST));
		list->data = con;
		Flooders = list_push (Flooders, list);
	    }
	}

	/* note that we pass only the data part of the packet */
	Protocol[l].handler (con, tag, len, pkt);
	Protocol[l].count++;
	Protocol[l].bytes += len;
	goto done;
    }
    log_message ("dispatch_command: unknown message: tag=%hu, length=%hu, data=%s",
	 tag, len, pkt);
    unknown_numeric.message = tag;
    unknown_numeric.count++;
    unknown_numeric.bytes += len;

    send_cmd (con, MSG_SERVER_NOSUCH, "Unknown command code %hu", tag);
#if DEBUG
    /* if this is a server connection, shut it down to avoid flooding the
       other server with these messages */
    if (ISSERVER (con))
    {
	u_char  ch;
	int     bytes;

	/* dump some bytes from the input buffer to see if it helps aid
	   debugging */
	bytes = con->recvbuf->datasize - con->recvbuf->consumed;
	/* print at most 128 bytes */
	if (bytes > 128)
	    bytes = 128;
	fprintf (stdout, "Dump(%d): ",
		 con->recvbuf->datasize - con->recvbuf->consumed);
	for (l = con->recvbuf->consumed; bytes > 0; bytes--, l++)
	{
	    ch = *(con->recvbuf->data + l);
	    fputc (isprint (ch) ? ch : '.', stdout);
	}
	fputc ('\n', stdout);
    }
#endif /* DEBUG */
  done:
    /* restore the byte we overwrite at the beginning of this function */
    *(pkt + len) = byte;
}

void
handle_connection (CONNECTION * con)
{
    int     n;
    u_short tag, len;

    ASSERT (validate_connection (con));

    if (ISSERVER (con))
    {
	/* server data is compressed.  read as much as we can and pass it
	   to the decompressor.  we attempt to read all data from the socket
	   in this loop, which will prevent unnecessary passes through the
	   main loop (since select would return immediately) */
	do
	{
	    n = READ (con->fd, Buf, sizeof (Buf));
	    if (n <= 0)
	    {
		if (n == -1)
		{
		    /* try to empty the socket each time, so we read until
		     * we hit this error (queue empty).  this should only
		     * happen in the rare event that the data in the queue
		     * is a multiple of sizeof(Buf)
		     */
		    if (N_ERRNO == EWOULDBLOCK)
			break;	/* not an error */
		    log_message
			("handle_connection: read: %s (errno %d) for host %s (fd %d)",
			 strerror (N_ERRNO), N_ERRNO, con->host, con->fd);
		}
		else
		    log_message ("handle_connection: EOF from %s", con->host);
		destroy_connection (con);
		return;
	    }

	    if (global.min_read > 0 && n < global.min_read)
	    {
		log_message ("handle_connection: %d bytes from %s", n,
			con->host);
	    }

	    global.bytes_in += n;
	    /* this can safely be called multiple times in this loop.  the
	     * decompressor will realloc the output buffer if there is not
	     * enough room to store everything
	     */
	    if (buffer_decompress (con->recvbuf, con->sopt->zin, Buf, n))
	    {
		destroy_connection (con);
		return;
	    }
	    /* if what we read was equal to sizeof(Buf) it's very likely
	     * that more data exists in the queue
	     */
	}
	while (n == sizeof (Buf));
    }
    else
    {
	/* create the input buffer if it doesn't yet exist */
	if (!con->recvbuf)
	{
	    con->recvbuf = CALLOC (1, sizeof (BUFFER));
	    if (!con->recvbuf)
	    {
		OUTOFMEMORY ("handle_connection");
		destroy_connection (con);
		return;
	    }
#if DEBUG
	    con->recvbuf->magic = MAGIC_BUFFER;
#endif
	    con->recvbuf->data = MALLOC (5);
	    if (!con->recvbuf->data)
	    {
		OUTOFMEMORY ("handle_connection");
		destroy_connection (con);
		return;
	    }
	    con->recvbuf->datamax = 4;
	}
	/* read the packet header if we haven't seen it already */
	while (con->recvbuf->datasize < 4)
	{
	    n = READ (con->fd, con->recvbuf->data + con->recvbuf->datasize,
		      4 - con->recvbuf->datasize);
	    if (n == -1)
	    {
		if (N_ERRNO != EWOULDBLOCK)
		{
		    log_message
			("handle_connection: read: %s (errno %d) for host %s",
			 strerror (N_ERRNO), N_ERRNO, con->host);
		    destroy_connection (con);
		}
		return;
	    }
	    else if (n == 0)
	    {
		destroy_connection (con);
		return;
	    }
	    global.bytes_in += n;
	    con->recvbuf->datasize += n;
	}
	/* read the packet body */
	memcpy (&len, con->recvbuf->data, 2);
	len = BSWAP16 (len);
	if (len > 0)
	{
	    if (len > Max_Command_Length)
	    {
		log_message ("handle_connection: %hu byte message from %s",
		     len, con->host);
		destroy_connection (con);
		return;
	    }

	    /* if there isn't enough space to read the entire body, resize the
	       input buffer */
	    if (con->recvbuf->datamax < 4 + len)
	    {
		/* allocate 1 extra byte for the \0 that dispatch_command()
		   requires */
		if (safe_realloc ((void **) &con->recvbuf->data, 4 + len + 1))
		{
		    OUTOFMEMORY ("handle_connection");
		    destroy_connection (con);
		    return;
		}
		con->recvbuf->datamax = 4 + len;
	    }
	    n = READ (con->fd, con->recvbuf->data + con->recvbuf->datasize,
		      len + 4 - con->recvbuf->datasize);
	    if (n == -1)
	    {
		/* since the header and body could arrive in separate packets,
		   we have to check for this here so we don't close the
		   connection on this nonfatal error.  we just wait for the
		   next packet to arrive */
		if (N_ERRNO != EWOULDBLOCK)
		{
		    log_message
			("handle_connection: read: %s (errno %d) for host %s",
			 strerror (N_ERRNO), N_ERRNO, con->host);
		    destroy_connection (con);
		}
		return;
	    }
	    else if (n == 0)
	    {
		log_message ("handle_connection: EOF from %s", con->host);
		destroy_connection (con);
		return;
	    }
	    con->recvbuf->datasize += n;
	    global.bytes_in += n;
	}
    }
    /* process as many complete commands as possible.  for a client this
       will be exactly one, but a server link may have sent multiple commands
       in one compressed packet */
    while (con->recvbuf->consumed < con->recvbuf->datasize)
    {
	/* if we don't have the complete packet header, wait until we
	   read more data */
	if (con->recvbuf->datasize - con->recvbuf->consumed < 4)
	    break;
	/* read the packet header */
	memcpy (&len, con->recvbuf->data + con->recvbuf->consumed, 2);
	memcpy (&tag, con->recvbuf->data + con->recvbuf->consumed + 2, 2);
	len = BSWAP16 (len);
	tag = BSWAP16 (tag);
	/* check if the entire packet body has arrived */
	if (con->recvbuf->consumed + 4 + len > con->recvbuf->datasize)
	    break;
	/* require that the client register before doing anything else */
	if (con->class == CLASS_UNKNOWN &&
	    (tag != MSG_CLIENT_LOGIN && tag != MSG_CLIENT_LOGIN_REGISTER &&
	     tag != MSG_CLIENT_REGISTER && tag != MSG_SERVER_LOGIN &&
	     tag != MSG_SERVER_LOGIN_ACK && tag != MSG_SERVER_ERROR &&
	     tag != 4 &&	/* unknown: v2.0 beta 5a sends this? */
	     tag != 300 && tag != 11 && tag != 920))
	{
	    log_message ("handle_connection: %s is not registered", con->host);
	    *(con->recvbuf->data + con->recvbuf->consumed + 4 + len) = 0;
	    log_message ("handle_connection: tag=%hu, len=%hu, data=%s", tag, len,
		 con->recvbuf->data + con->recvbuf->consumed + 4);

#if 0
	    /* not sure why the official servers do this, but lets
	     * be compatible.
	     */
	    send_cmd (con, MSG_SERVER_ECHO, "%hu: %s", tag,
		      con->recvbuf->data + con->recvbuf->consumed + 4);

	    con->recvbuf->consumed += 4 + len;
	    break;
#else
	    send_cmd (con, MSG_SERVER_ERROR, "invalid command");
	    destroy_connection (con);
	    return;
#endif
	}

	if (Servers && ISUSER (con))
	{
	    /* check for end of share/unshare sequence.  in order to avoid
	       having to send a single message for each shared file,
	       the add_file and remove_file commands set a flag noting the
	       start of a possible series of commands.  this routine checks
	       to see if the end of the sequence has been reached (a command
	       other than share/unshare has been issued) and then relays
	       the final result to the peer servers.
	       NOTE: the only issue with this is that if the user doesn't
	       issue any commands after sharing files, the information will
	       never get passed to the peer servers.  This is probably ok
	       since this case will seldom happen */
	    if (con->user->sharing)
	    {
		if (tag != MSG_CLIENT_ADD_FILE
		    && tag != MSG_CLIENT_SHARE_FILE
		    && tag != MSG_CLIENT_ADD_DIRECTORY)
		{
		    pass_message_args (con, MSG_SERVER_USER_SHARING,
				       "%s %hu %u", con->user->nick,
				       con->user->shared, con->user->libsize);
		    con->user->sharing = 0;
		}
	    }
	    else if (con->user->unsharing)
	    {
		if (tag != MSG_CLIENT_REMOVE_FILE)
		{
		    pass_message_args (con, MSG_SERVER_USER_SHARING,
				       "%s %hu %u", con->user->nick,
				       con->user->shared, con->user->libsize);
		    con->user->unsharing = 0;
		}
	    }
	}
	/* call the protocol handler */
	dispatch_command (con, tag, len,
			  con->recvbuf->data + con->recvbuf->consumed + 4);
	/* mark data as processed */
	con->recvbuf->consumed += 4 + len;
    }
    if (con->recvbuf->consumed)
    {
	n = con->recvbuf->datasize - con->recvbuf->consumed;
	if (n > 0)
	{
	    /* shift down unprocessed data */
	    memmove (con->recvbuf->data,
		     con->recvbuf->data + con->recvbuf->consumed, n);
	}
	con->recvbuf->datasize = n;
	con->recvbuf->consumed = 0;	/* reset */
    }
}
