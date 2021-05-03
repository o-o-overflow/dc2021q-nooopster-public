/* $Id: win32-support.h,v 1.3 2001/09/30 21:56:02 drscholl Exp $
 *
 *    Open Source Napster Server - Peer-To-Peer Indexing/Chat Daemon
 *    Copyright (C) 2001  drscholl@users.sourceforge.net
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program; if not, write to the Free Software
 *    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/* This file contains definitions useful for porting UNIX code to the Win32
 * platform using the Microsoft Visual C++ compiler.
 */

#include <windows.h>

/* the next two #defines are needed for zlib */
#define _WINDOWS
#define ZLIB_DLL
#include "zlib.h"

#define PACKAGE "opennap"
#define VERSION "0.44"

#define getopt _getopt
#define READ(a,b,c) recv(a,b,c,0)
#define WRITE(a,b,c) send(a,b,c,0)
#define CLOSE closesocket
#undef SOCKOPTCAST
#define SOCKOPTCAST (char*)
#define EINPROGRESS WSAEINPROGRESS
#define EWOULDBLOCK WSAEWOULDBLOCK
#define ENOBUFS WSAENOBUFS
#define ENOTSOCK WSAENOTSOCK
#define _POSIX_PATH_MAX 256

#define strcasecmp stricmp
#define strncasecmp strnicmp
#define vsnprintf _vsnprintf
#define snprintf _snprintf
#define getuid() 0		/* just fake it */
#define getpid() 0		/* just fake it */

extern char *optarg;
extern int optind;

extern int _getopt (int, char **, char *);
