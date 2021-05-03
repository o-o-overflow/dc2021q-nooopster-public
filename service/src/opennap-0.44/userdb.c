/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id: userdb.c,v 1.34 2001/09/22 05:52:06 drscholl Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <limits.h>
#include "opennap.h"
#include "debug.h"

HASH   *User_Db = 0;

int
get_level (const char *s)
{
    if (!strncasecmp ("lee", s, 3))
	return LEVEL_LEECH;
    if (!strncasecmp ("use", s, 3))
	return LEVEL_USER;
    if (!strncasecmp ("mod", s, 3))
	return LEVEL_MODERATOR;
    if (!strncasecmp ("eli", s, 3))
	return LEVEL_ELITE;
    if (!strncasecmp ("adm", s, 3))
	return LEVEL_ADMIN;
    return -1;
}

void
userdb_free (USERDB * p)
{
    if (p)
    {
	if (p->nick)
	    FREE (p->nick);
#if EMAIL
	if (p->email)
	    FREE (p->email);
#endif
	if (p->password)
	    FREE (p->password);
	FREE (p);
    }
}

int
userdb_init (void)
{
    FILE   *fp;
    int     ac, regen = 0, level;
    char   *av[7], path[_POSIX_PATH_MAX];
    USERDB *u;

    snprintf (path, sizeof (path), "%s/users", Config_Dir);
    fp = fopen (path, "r");
    if (!fp)
    {
	logerr ("userdb_init", path);
	return -1;
    }
    User_Db = hash_init (257, (hash_destroy) userdb_free);
    log_message ("userdb_init: reading %s", path);
    if (fgets (Buf, sizeof (Buf), fp))
    {
	if (strncmp (":version 1", Buf, 10))
	{
	    regen = 1;
	    rewind (fp);
	}
    }
    while (fgets (Buf, sizeof (Buf), fp))
    {
	ac = split_line (av, FIELDS (av), Buf);
	if (ac >= 6)
	{
	    if (invalid_nick (av[0]))
	    {
		log_message ("userdb_init: %s: invalid nickname", av[0]);
		continue;
	    }
	    u = CALLOC (1, sizeof (USERDB));
	    if (u)
	    {
		u->nick = STRDUP (av[0]);
		if (regen)
		    u->password = generate_pass (av[1]);
		else
		    u->password = STRDUP (av[1]);
#if EMAIL
		u->email = STRDUP (av[2]);
#endif
	    }
	    if (!u || !u->nick || !u->password
#if EMAIL
		|| !u->email
#endif
		)
	    {
		OUTOFMEMORY ("userdb_init");
		if (u)
		    userdb_free (u);
		fclose (fp);
		return -1;
	    }
	    level = get_level (av[3]);
	    if (level < 0 || level > LEVEL_ELITE)
	    {
		log_message ("userdb_init: invalid level %s for user %s", av[3],
		     u->nick);
		level = LEVEL_USER;
	    }
	    u->level = level;
	    u->created = atol (av[4]);
	    u->lastSeen = atol (av[5]);
	    if (ac > 6)
		u->flags = atoi (av[6]);	/* u_short, atoi() is fine */
	    hash_add (User_Db, u->nick, u);
	}
	else
	{
	    log_message ("userdb_init: bad user db entry");
	    print_args (ac, av);
	}
    }
    fclose (fp);
    log_message ("userdb_init: %d registered users", User_Db->dbsize);
    /* reformat to version 1 specification */
    if (regen)
	userdb_dump ();
    return 0;
}

static void
dump_userdb (USERDB * db, FILE * fp)
{
    if (global.current_time - db->lastSeen >= Nick_Expire)
    {
	if (db->level < LEVEL_MODERATOR)
	{
	    strcpy (Buf, ctime (&db->lastSeen));
	    Buf[strlen (Buf) - 1] = 0;
	    log_message ("dump_userdb: %s has expired (last seen %s)", db->nick,
		 Buf);
	    hash_remove (User_Db, db->nick);
	    return;
	}
	/* warn, but dont nuke expired accounts for privileged users */
	log_message ("dump_userdb: %s has expired (ignored: level=%s)",
	     db->nick, Levels[db->level]);
    }

    fputs (db->nick, fp);
    fputc (' ', fp);
    fputs (db->password, fp);
    fputc (' ', fp);
#if EMAIL
    fputs (db->email, fp);
#else
    fputs ("unknown", fp);	/* dummy value to keep file format the same */
#endif
    fputc (' ', fp);
    fputs (Levels[db->level], fp);
    fputc (' ', fp);
    fprintf (fp, "%d %u %hu", (int) db->created, (int) db->lastSeen,
	     db->flags);
#ifdef WIN32
    fputs ("\r\n", fp);
#else
    fputc ('\n', fp);
#endif
}

int
userdb_dump (void)
{
    FILE   *fp;
    char    path[_POSIX_PATH_MAX], tmppath[_POSIX_PATH_MAX];

    log_message ("userdb_dump: dumping user database");
    snprintf (tmppath, sizeof (tmppath), "%s/users.tmp", Config_Dir);
    fp = fopen (tmppath, "w");
    if (!fp)
    {
	logerr ("userdb_dump", tmppath);
	return -1;
    }
#ifdef WIN32
    fputs (":version 1\r\n", fp);
#else
    fputs (":version 1\n", fp);
#endif
    hash_foreach (User_Db, (hash_callback_t) dump_userdb, fp);
    if (fflush (fp))
    {
	logerr ("userdb_dump", "fflush");
	fclose (fp);
	return -1;
    }
    if (fclose (fp))
    {
	logerr ("userdb_dump", "fclose");
	return -1;
    }
    snprintf (path, sizeof (path), "%s/users", Config_Dir);
    if (unlink (path))
	logerr ("userdb_dump", "unlink");	/* not fatal, may not exist */
    if (rename (tmppath, path))
    {
	logerr ("userdb_dump", "rename");
	return -1;
    }
    log_message ("userdb_dump: wrote %d entries", User_Db->dbsize);
    return 0;
}

/* create a default USERDB record from the existing user */
USERDB *
create_db (USER * user)
{
    USERDB *db = CALLOC (1, sizeof (USERDB));

    if (db)
    {
	db->nick = STRDUP (user->nick);
	db->password = generate_pass (user->pass);
#if EMAIL
	snprintf (Buf, sizeof (Buf), "anon@%s", Server_Name);
	db->email = STRDUP (Buf);
#endif
	db->level = user->level;
	db->created = global.current_time;
	db->lastSeen = global.current_time;
    }
    if (!db || !db->nick || !db->password
#if EMAIL
	|| !db->email
#endif
	)
    {
	OUTOFMEMORY ("create_db");
	userdb_free (db);
	return 0;
    }
    if (hash_add (User_Db, db->nick, db))
    {
	userdb_free (db);
	return 0;
    }
    return db;
}
