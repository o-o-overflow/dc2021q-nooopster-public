/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id: list.c,v 1.15 2001/03/06 06:49:52 drscholl Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include "list.h"
#include "debug.h"

LIST   *
list_new (void *p)
{
    LIST   *list = CALLOC (1, sizeof (LIST));

    if (list)
	list->data = p;
    return list;
}

/* remove the element matching `data' from the list */
LIST   *
list_delete (LIST * list, void *data)
{
    LIST  **ptr, *tmp;

    ASSERT (list != 0);
    ASSERT (data != 0);
    for (ptr = &list; *ptr; ptr = &(*ptr)->next)
    {
	ASSERT (VALID_LEN (*ptr, sizeof (LIST)));
	if ((*ptr)->data == data)
	{
	    tmp = *ptr;
	    *ptr = (*ptr)->next;
	    FREE (tmp);
	    break;
	}
    }
    return list;
}

LIST   *
list_append (LIST * l, LIST * b)
{
    LIST  **r = &l;

    while (*r)
    {
	ASSERT (VALID_LEN (*r, sizeof (LIST)));
	r = &(*r)->next;
    }
    *r = b;
    return l;
}

LIST   *
list_append_data (LIST * l, void *d)
{
    LIST   *list;

    ASSERT (d != 0);
    LIST_NEW (list, d);
    return (list_append (l, list));
}

void
list_free (LIST * l, list_destroy_t cb)
{
    LIST   *t;

    while (l)
    {
	ASSERT (VALID_LEN (l, sizeof (LIST)));
	t = l;
	l = l->next;
	if (cb)
	    cb (t->data);
	FREE (t);
    }
}

int
list_count (LIST * list)
{
    int     count = 0;

    for (; list; list = list->next)
    {
	ASSERT (VALID_LEN (list, sizeof (LIST)));
	count++;
    }
    return count;
}

LIST   *
list_find (LIST * list, void *data)
{
    for (; list; list = list->next)
    {
	ASSERT (VALID_LEN (list, sizeof (LIST)));
	if (list->data == data)
	    return list;
    }
    return 0;
}

#if DEBUG
int
list_validate (LIST * list)
{
    for (; list; list = list->next)
    {
	ASSERT_RETURN_IF_FAIL (VALID_LEN (list, sizeof (LIST)), 0);
    }
    return 1;
}
#endif

LIST   *
list_push (LIST * head, LIST * elem)
{
    elem->next = head;
    return elem;
}

void
list_foreach (LIST * list, list_callback_t func, void *arg)
{
    while (list)
    {
	func (list->data, arg);
	list = list->next;
    }
}
