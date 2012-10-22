#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xmalloc.h"
#include "config.h"
#include "user.h"


/* Initialises the user structure 
 * returns a pointer to it or null if there is an error
 */
auth_user_p 
init_user(const char *username, const char *passwd, options_p opt)
{
	char *ptr, *ptr2;
	int len = 0;

	assert(username != NULL);
	assert(passwd != NULL);

	auth_user_p user;
 	XMALLOC(user,sizeof(auth_user));
	ptr = ptr2 = NULL;

	/* We check whether we have a username of type user@realm */
	ptr = strchr(username, '@');
	/* If yes , we copy the username and realm in the places */
	if(ptr) {
		len = ptr-username;
		XMALLOC(user->name, (len+1)*sizeof(char));
		strncpy(user->name, username, len);
		user->name[len] = '\0';
		/* We copy the realm */
		ptr++;
		ptr2 = ptr;
		/* this is the case user@ , we copy the default realm */
		if(*ptr == '\0') { 
			if(opt->default_realm) {
				len = strlen(opt->default_realm); /* default realm should be necessary */
				XMALLOC(user->realm, (len+1)*sizeof(char));
				strncpy(user->realm, opt->default_realm, len);
				user->realm[len] = '\0';
			}
			else
				user->realm = NULL;
		}

		while(*ptr2++ != '\0') ;
		
		len = ptr2 - ptr;
		XMALLOC(user->realm, (len+1)*sizeof(char));
		strncpy(user->realm, ptr, len);
		user->realm[len] = '\0';
	}
	else { /* copy the username and the default realm */
		len = strlen(username);
		XMALLOC(user->name, (len+1)*sizeof(char));
		strncpy(user->name, username, len);
		user->name[len] = '\0';
	
		if(opt->default_realm) {
			len = strlen(opt->default_realm);
			XMALLOC(user->realm, (len+1)*sizeof(char));
			strncpy(user->realm,opt->default_realm,len);
			user->realm[len] = '\0';
		}
		else {
			user->realm = NULL;
		}
	}

	/* We copy the password */

	len = strlen(passwd);
	XMALLOC(user->passwd, (len+1)*sizeof(char));
	strncpy(user->passwd, passwd, len);
	user->passwd[len] = '\0';

	/* The other structures */

	user->groups = NULL;
	user->dyn_groups = NULL;
	user->roles = NULL;
	user->dyn_roles = NULL;

	return user;
}

void 
free_user(auth_user_p user)
{
	if(user->name)
		FREE(user->name);
	if(user->realm)
		FREE(user->realm);
	if(user->passwd)
		FREE(user->passwd);
	FREE(user);
}
