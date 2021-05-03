/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id: glob.c,v 1.5 2001/03/06 06:49:52 drscholl Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include "opennap.h"

/* returns >0 if the pattern matches, 0 if the pattern does not match.
 * the match is case-insensitive
 */
int
glob_match (const char *pattern, const char *s)
{
    const char *ptr;

    while (*pattern && *s)
    {
	if (*pattern == '*')
	{
	    while (*pattern == '*' || *pattern == '?')
		pattern++;
	    if (!*pattern)
	    {
		/* match to end of string */
		return 1;
	    }
	    /* recursively attempt to match the rest of the string, using the
	     * longest match first
	     */
	    ptr = s + strlen (s);
	    for (;;)
	    {
		while (ptr > s && tolower (*(ptr - 1)) != tolower (*pattern))
		    ptr--;
		if (ptr == s)
		    return 0;	/* no match */
		if (glob_match (pattern + 1, ptr))
		    return 1;
		ptr--;
	    }
	    /* not reached */
	}
	else if (*pattern == '?' || tolower (*pattern) == tolower (*s))
	{
	    pattern++;
	    s++;
	}
	else
	    return 0;		/* no match */
    }
    return ((*pattern || *s) ? 0 : 1);
}
