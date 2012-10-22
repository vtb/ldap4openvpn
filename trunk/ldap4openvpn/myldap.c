#include <sys/time.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <ldap.h>

#include "config.h"
#include "myldap.h"
#include "xmalloc.h"

static int ldap_connect(ldap_context_p ldc_p);
static int ldap_reconnect(ldap_context_p ldc_p);
static char ** list_to_array(const lista_p lista);
static int my_ldap_search_st(ldap_context_p ldc_p, char *filter, char **attrs, int attrsonly, LDAPMessage **res);


/* Used to initialise the ldap connection using a speficic ldc 
 * return 0 on success. != 0 on failure. The exact failure messages
 * are the same with ldap_connect. (Should be defined at myldap.h at some point)
 * returns 4 in case there ldc_p structure is not properly initialized
 */
int 
ldap_start(ldap_context_p ldc_p)
{
	int r = 0;
	assert (ldc_p != NULL);
	if(ldc_p->host == NULL || ldc_p->bind_dn == NULL || ldc_p->bind_passwd == NULL )
		return 4;
	if(ldc_p->ld != NULL)
		r = ldap_reconnect(ldc_p);
	else
		r = ldap_connect(ldc_p);
	return r;
}

/* Does the actual connect to LDAP. 
 * Input: ldc_p: Pointer to ldap_context structure that keeps the ldap info
 * Returns : 0 on success
 *			 1 if there initialisation to ldap fails
 *           2 if there is a problem setting the predined options
 *           3 if there is failure in binding
 */
static int 
ldap_connect(ldap_context_p ldc_p)
{
	int r = 0;
	ldc_p->ld = ldap_init(ldc_p->host, LDAP_PORT);
	if(ldc_p->ld == NULL)
		return 1;
	
	/* init options */
	 r = ldap_set_option(ldc_p->ld, LDAP_OPT_PROTOCOL_VERSION, (void *) &(ldc_p->version));

	 if (r == LDAP_OPT_SUCCESS)
	 r = ldap_set_option (ldc_p->ld, LDAP_OPT_RESTART, (void *) &(ldc_p->restart));

	 if (r == LDAP_OPT_SUCCESS)
	 r = ldap_set_option (ldc_p->ld, LDAP_OPT_SIZELIMIT, (void *) &(ldc_p->sizelimit));

	 if (r == LDAP_OPT_SUCCESS) 
	 r = ldap_set_option (ldc_p->ld, LDAP_OPT_NETWORK_TIMEOUT, (void *) &(ldc_p->net_timeout));

	 if (r == LDAP_OPT_SUCCESS)
	 r = ldap_set_option (ldc_p->ld, LDAP_OPT_DEREF, (void *) &(ldc_p->deref));

	 if (r == LDAP_OPT_SUCCESS)
	 r = ldap_set_option (ldc_p->ld, LDAP_OPT_REFERRALS, (void *) &(ldc_p->refer));

	if(r != LDAP_OPT_SUCCESS)
		return 2;

	/* The actual binding */

	r = ldap_simple_bind_s(ldc_p->ld, ldc_p->bind_dn, ldc_p->bind_passwd);

	if(r != LDAP_SUCCESS)
		return 3;

	return 0;

}

void 
free_ldap_context(ldap_context_p ldc_p)
{
	assert(ldc_p != NULL);

	if(ldc_p->host)
		FREE(ldc_p->host);
	if(ldc_p->bind_dn)
		FREE(ldc_p->bind_dn);
	/* bind_dn passwd is not malloced .. if it is we should free it */
	if(ldc_p->base_dn)
		FREE(ldc_p->base_dn);
	if(ldc_p->objectclass)
		FREE(ldc_p->objectclass);
	FREE(ldc_p);	
}

/* Does the ldap reconnection in case of failure. The return values are same as
 * ldap_connect.
 */
static int 
ldap_reconnect(ldap_context_p ldc_p)
{
	int r = 0;
	r = ldap_unbind(ldc_p->ld); /* Perhaps we should do some checking .. but again if it 
fails I don't believe it is much of a problem */
	r = ldap_connect(ldc_p);
	return r;	
	
}

static int
my_ldap_search_st(ldap_context_p ldc_p, char *filter, char **attrs, int attrsonly, LDAPMessage **res)
{
	int r;
	r = ldap_search_st(ldc_p->ld, ldc_p->base_dn, ldc_p->scope, filter, attrs,
                     attrsonly, &(ldc_p->net_timeout), res);
  
	if ((r == LDAP_SERVER_DOWN || r == LDAP_CONNECT_ERROR) && !ldap_reconnect(ldc_p)) {
		r = ldap_search_st(ldc_p->ld, ldc_p->base_dn, ldc_p->scope, filter, attrs,
                         attrsonly, &(ldc_p->net_timeout), res);
	}

	return r;
}


/* Initialises the ldap configuration so that is possible to connect 
 * Returns a pointer to the ldap_context structure malloced. NULL if there is 
 * an error 
 */
ldap_context_p 
ldap_init_config(options_p opt, auth_user_p user, int useManager)
{
	ldap_context_p ldc;
	XMALLOC(ldc,sizeof(ldap_context));
	ldc->host = createLdapHost(opt,user);
	if(!ldc->host) {
		FREE(ldc);
		ldc = NULL;
	}

	if(ldc) {	
		if(useManager) {
			ldc->bind_dn = createManagerDN(opt,user);
			ldc->bind_passwd = opt->manager_passwd;
		}
		else {
			ldc->bind_dn = createuserDN(opt,user);
			ldc->bind_passwd = user->passwd;
		}
	
		if(!ldc->bind_dn) {
			FREE(ldc);
			ldc = NULL;
		}
		else if(!ldc->bind_passwd) {
			FREE(ldc->host);
			FREE(ldc->bind_dn);
			FREE(ldc);
			ldc = NULL;
		}
	}
	
	if(ldc) {
		ldc->base_dn = createBaseDN(opt,user);
		if(!ldc->base_dn) {
			FREE(ldc->host);
			FREE(ldc->bind_dn);
			FREE(ldc);
			ldc = NULL;
		}
	}	

	if(ldc) {	
		ldc->ld = NULL;
		/* TODO: The rest init should go here */

		ldc->scope = LDAP_SCOPE_SUBTREE;
		ldc->deref = LDAP_DEREF_NEVER;
		ldc->refer = (int) LDAP_OPT_OFF;
		ldc->restart = (int) LDAP_OPT_ON;
		ldc->version = LDAP_VERSION3;

		/* These should be conf options */
		ldc->net_timeout.tv_sec = (time_t) 5;
		ldc->net_timeout.tv_usec = (time_t) 0;

		ldc->sizelimit = 200;
		ldc->objectclass = NULL;
	}
	
	return ldc;
}

/* converts a list to a char ** needed for ldap_search */
static char **
list_to_array(const lista_p lista)
{
	int i = 0;
	lista_p iterator = lista;
	char **array = NULL;

	/* Normally the lista shouldn't be NULL, but we can have this NULL so that we 
         * allow a way to retrieve all the attributes. NOTE: BAD BAD BAD idea 
	 */
	if (lista == NULL)
		return NULL;

	/* I believe that having an integer counting the number of elements
	 * of the list and calling malloc once is faster than calling realloc
	 * each time we want to add an element to the array */
	while ( iterator != NULL) {
		i++;
		iterator = iterator->next;
	}

	XMALLOC(array, i*sizeof(char *));

	for(iterator=lista, i = 0; iterator != NULL ; iterator = iterator->next, i++) 
		array[i] = iterator->key;

	array[i] = NULL;

	return array;

}


int 
ldap_verify_user(ldap_context_p manager_ldap, auth_user_p user, options_p opt, char **ldap_results)
{
	int r;
	char **attrs, *filter;
	LDAPMessage *filter_results = NULL;

	filter = createLoginFilter(opt,user);
	
	/* If there is a problem constructing the filter. then return an error.
	 * This is a reasonable thing to do, since if we cannot create the filter
	 * the user shouldn't be able to login
         * TODO: add some debugging info 
	 */
	if(!filter) 
		return 1;

	attrs = list_to_array(opt->attributes);

	r = my_ldap_search_st(manager_ldap, filter, attrs, 1, &filter_results); 

	/* We don't need these data any more */
	if(attrs != NULL) {
		FREE(attrs);
		attrs = NULL;
	}
	FREE(filter);
	filter = NULL;

	if(r != LDAP_SUCCESS) 
		return 1;
	
	r = ldap_count_entries(manager_ldap->ld, filter_results);

	/* We don't need the results now */
	ldap_msgfree(filter_results);

	if((r == -1) || (r == 0))
		return 1;
	else
		return 0;
}
