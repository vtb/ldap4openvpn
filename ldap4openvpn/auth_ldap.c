#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <ldap.h>

#include "config.h"
#include "myldap.h"
#include "xmalloc.h"

#include "openvpn-plugin.h"


#ifdef MYMALLOC_DEBUG
#define DEBUG(verb) ((verb) >= 7)
int numOfAllocs = 0;
#endif

struct plugin_context {
	const char *username;
	const char *password;
	options_p opt;
	lista_p manager_connect;
};

static const char *get_env (const char *__name, const char *__envp[]);
static void free_manager_connect(lista_p manager_connect);

static const char *
get_env (const char *name, const char *envp[])
{
  if (envp)
    {
      int i;
      const int namelen = strlen (name);
      for (i = 0; envp[i]; ++i)
	{
	  if (!strncmp (envp[i], name, namelen))
	    {
		  const char *cp = envp[i] + namelen;
	      if (*cp == '=')
		return cp + 1;
	    }
	}
    }
  return NULL;
}

OPENVPN_EXPORT openvpn_plugin_handle_t
openvpn_plugin_open_v1 (unsigned int *type_mask, const char *argv[], const char *envp[])
{
	const char *fname;
	struct plugin_context *context;
	int r;

	if(argv[1] != NULL ) /* XXX: Don't like this check */
		fname = argv[1];
	 else
		fname = DEFAULT_CONFIG;
	
	/*
	* Allocate our context
	*/
	context = (struct plugin_context *) calloc (1, sizeof (struct plugin_context));
	context->opt = (options_p) calloc(1, sizeof(options));
	context->manager_connect = NULL;

	r = read_config_file(fname, context->opt);	

	if(r) {
		printf("Error opening config file %s\n", fname);
		exit(1);
	}


	/*
	* Set the username/password we will require.
	context->username = "foo";
	context->password = "bar";
	*/

	/*
	* We are only interested in intercepting the
	* --auth-user-pass-verify callback.
	*/
	*type_mask = OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);

#ifdef MYMALLOC_DEBUG
	fprintf(stderr, "After opening numOfAllocs : %d\n ", numOfAllocs); 
#endif

	return (openvpn_plugin_handle_t) context;
}

OPENVPN_EXPORT int
openvpn_plugin_func_v1 (openvpn_plugin_handle_t handle, const int type, const char *argv[], const char *envp[])
{
	options_p myoptions;
	int r;
	ldap_context_p user_ldap, manager_ldap;
	auth_user_p  user;
	const char *username, *passwd;
	struct plugin_context *context;
	lista_p manager_connect;
	char **ldap_results = NULL;

	context = (struct plugin_context *) handle;
	myoptions = context->opt;
	manager_connect = context->manager_connect;
	username = get_env("username", envp);
	passwd = get_env("password", envp);

	user = init_user(username, passwd, myoptions);
	user_ldap = ldap_init_config(myoptions, user, 0);

	r = ldap_start(user_ldap);

	if(r) {
		switch(r) {
			case 1 :
				printf("Error init ldap\n");
				break;
			case 2:
				printf("Error setting options\n");
				break;
			case 3:
				printf("Error unable to bind\n");
				break;
		}
	}
	ldap_unbind(user_ldap->ld); /* We don't need to keep this binding */

/* the manager connections are going here 
 * First we check whether we already have a manager's connection on the host
 * if we don't we create one
 * we use the manager connection
 * if we created a new one we add it to the list 
 */

	if(!r) {

		manager_ldap = findElement(manager_connect, user_ldap->host);
		if(manager_ldap == NULL) {
		/* Create a new connection for that and save it*/
	
			manager_ldap = ldap_init_config(myoptions,user,1);
			r = ldap_start(manager_ldap);
			if(r) {
				switch(r) {
					case 1:
						printf("Error init ldap\n");
						break;
					case 2:
						printf("Error setting options\n");
						break;
					case 3:
						printf("Unable to bind\n");
						break;
				}
			}
			else 
			/* Everything O.K. so we add the manager ldap to the list */
				addtolista(&(context->manager_connect), (void *) manager_ldap, manager_ldap->host);
	
		}

	
		/* If everything ok, use the connection */
		if(!r)
			r = ldap_verify_user(manager_ldap, user, myoptions, ldap_results);
	}

	if(!r)
		r = OPENVPN_PLUGIN_FUNC_SUCCESS;
	else
		r = OPENVPN_PLUGIN_FUNC_ERROR;
	
	/* At this point all the free stuff should go */
	free_user(user);
	free_ldap_context(user_ldap);
	/* We keep the options */
#ifdef MYMALLOC_DEBUG
	fprintf(stderr, "After opening numOfAllocs : %d\n", numOfAllocs); 
#endif
	return r;
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1 (openvpn_plugin_handle_t handle)
{
	struct plugin_context *context = (struct plugin_context *) handle;
	/* We should free also the options stuff */
	free_manager_connect(context->manager_connect);
	free_options(context->opt);
#ifdef MYMALLOC_DEBUG
	fprintf(stderr, "After opening numOfAllocs : %d\n ", numOfAllocs); 
#endif
	free (context);
}


static void
free_manager_connect(lista_p manager_connect)
{
	lista_p iterator, previous; 

	iterator = manager_connect;
	while(iterator) {
/*		FREE(iterator->key);  we don't need to free the memory for host since it is 
just a pointer to manager->data->host */
		ldap_unbind(((ldap_context_p) iterator->data)->ld); /* unbind from the ldap before freeing the memory */
		free_ldap_context(iterator->data);
		previous = iterator;
		iterator = iterator->next;
		FREE(previous);
	}
	FREE(manager_connect);
}
