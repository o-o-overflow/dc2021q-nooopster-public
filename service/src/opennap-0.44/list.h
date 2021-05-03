/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id: list.h,v 1.8 2000/12/27 09:51:19 drscholl Exp $ */

#ifndef list_h
#define list_h

typedef struct list LIST;

struct list {
    void *data;
    LIST *next;
};

/* prototype for list_free() callback function */
typedef void (*list_destroy_t) (void *);

typedef void (*list_callback_t) (void *, void *);

/* create a new list struct with the given data */
LIST *list_new (void *);

/* removes the specified element from the list */
LIST *list_delete (LIST *, void *);

/* append an element to the list */
LIST *list_append (LIST *, LIST *);

LIST *list_append_data (LIST *, void *);

/* add element to beginning of list */
LIST *list_push (LIST *, LIST *);

/* free a list element */
void list_free (LIST *, list_destroy_t);

/* return the number of items in a list */
int list_count (LIST *);

LIST *list_find (LIST *, void *);

int list_validate (LIST *);

void list_foreach (LIST *, list_callback_t, void *);

#if DEBUG
#define LIST_NEW(p,d) { p = CALLOC (1, sizeof (LIST)); if (p) (p)->data = d; }
#else
#define LIST_NEW(p,d) p = list_new (d)
#endif /* DEBUG */

#endif /* list_h */
