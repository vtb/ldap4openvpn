/* This file should have all the important ldap informations and the methods needed to 
 * connect to ldap. It is used as a helper file for the ldap stuff 
 *    Initialised : arisg. 12/12/2005 . Based on cyrus_ldap.c from uoa cyrus imap 
 */

#ifndef MYLDAP_H
#define MYLDAP_H
#include <sys/time.h>

/* We need the basic info, since we don't want to replicate the info between 
 * the options and the ldap stuff. However since some options exist using wildcards
 * we have to mirror them with the specific info.
 * Each ldap_context represents the connection to 1 ldap server with specific criteria
 */
struct ldap_context
{
	char *host; /*Perhaps not needed if you have them in a list */
	LDAP *ld;
	char *bind_dn;
	char *bind_passwd;
	int version;
	char *base_dn;
	int scope;
	char *objectclass;
	int sizelimit;     /* this one currently applies only to the number of dynamic roles that may returned */
	int restart;
	struct timeval net_timeout;
	int deref;
	int refer;
};

typedef struct ldap_context ldap_context;
typedef struct ldap_context* ldap_context_p;

int ldap_start(ldap_context_p __ldc_p);
void free_ldap_context(ldap_context_p __ldc_p);
ldap_context_p ldap_init_config(options_p __opt, auth_user_p __user, int __userManager);
int ldap_verify_user(ldap_context_p __manager_ldap, auth_user_p __user, options_p __opt, char **__ldap_results);

#endif /* MYLDAP_H */
