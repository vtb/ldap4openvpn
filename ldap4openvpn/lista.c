#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lista.h"
#include "xmalloc.h"



/* returns the data of a list , that is found with the key
 * the search methos is just dummy serial */
void *
findElement(lista *listal, char *key)
{
    struct lista *iterator;
    iterator = listal;
    while (iterator != NULL) {
        if(!strcmp(listal->key,key)) 
            return listal->data;    
        else
            iterator = iterator->next;  
     }
     return NULL;
}

 
/* removes an element from a list. The element is identified by the key 
 * NOTE: the element memory is NOT freed */
void 
deletefromlista(struct lista **list, char *key)
 {
    struct lista *iterator, *previous;
    iterator = previous = (*list);
    
    while (iterator != NULL)
    {   
        if (!strcmp(iterator->key,key))
        {
            if (iterator == (*list))
                (*list) = iterator->next;
            else
                previous->next = iterator->next;
    	    FREE(iterator);
	    return;
        }
    previous = iterator;
    iterator = iterator->next;
    }
}

/* Adds an element to the end list. Constructs the lista if doesn't exist */ 
void 
addtolista(struct lista **list, void *data, char *key)
{
    struct lista *wk, *prev = NULL, *new;
    if( list == NULL) 
        return;
    if ((*list) == NULL) {
        XMALLOC((*list),sizeof(struct lista));
	(*list)->key = key;
        (*list)->data = data;
        (*list)->next = NULL;
    }
    else {
        XMALLOC(new,sizeof(struct lista));
	new->key = key; 
        new->data = data;
	wk = (*list);
	while(wk != NULL) {
		prev = wk;
		wk = wk->next;
	}
        new->next = wk;
        prev->next = new;
    }
}
