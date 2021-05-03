/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id: client_quit.c,v 1.16 2001/09/22 05:52:06 drscholl Exp $ */

#include "opennap.h"
#include "debug.h"

/* handle notification that a user has quit */
/* <user> */
HANDLER (client_quit)
{
    USER *user;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_SERVER_CLASS ("client_quit");
    user = hash_lookup (Users, pkt);
    if (!user)
    {
	log_message ("client_quit: can't find user %s", pkt);
	return;
    }
    ASSERT (validate_user (user));
    if (ISSERVER (user->con))
    {
	pass_message_args (con, tag, "%s", user->nick);
	hash_remove (Users, user->nick);
    }
    else
	log_message ("client_quit: recieved QUIT for local user %s!", user->nick);
}
