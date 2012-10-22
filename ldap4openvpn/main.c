#include <stdio.h>
#include <stdlib.h>
#include <ldap.h>
#include <string.h>

#include "config.h"
#include "myldap.h"


static const char *get_env (const char *__name, const char *__envp[]);

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


int main(int argc, char *argv[], const char *env[])
{
	options myoptions;
	int r;
	const char *fname;
	ldap_context_p user_ldap, manager_ldap;
	auth_user_p user;
	const char *username, *passwd;
	char **ldap_results;
	
	if(argc > 1)
		fname = argv[1];
	else 
		fname = DEFAULT_CONFIG;

	r = read_config_file(fname, &myoptions);
	
	if(r) {
		printf("Error opening config file %s\n", fname);
		exit(1);
	}
	
	
	username = get_env("username", env);
	passwd = get_env("password", env);

	user = init_user(username, passwd, &myoptions);	
	user_ldap = ldap_init_config(&myoptions, user, 0);
	
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

/* the manager connections are going here
 * First we check whether we already have a manager's connection on the host
 * if we don't we create one
 * we use the manager connection
 * if we created a new one we add it to the list
 */

        /* Create a new connection for that and save it*/

	if(!r) {

                manager_ldap = ldap_init_config(&myoptions,user,1);
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


        /* Use the connection */

        r = ldap_verify_user(manager_ldap, user, &myoptions, ldap_results);

	}

        /* At this point all the free stuff should go */
        free_user(user);
        free_ldap_context(user_ldap);


	if(!r) 
		printf("binding ok\n");	
	return r;	
}
