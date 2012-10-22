#ifndef CONFIG_H
#define CONFIG_H

#include "lista.h"

/* Generic type for variables */
/* XXX : Den eimai akomh 100% sigoyros poy tha xrhsimopoihthei ayto */
struct variable {
	char *name;
	void *value;
};

typedef struct variable variable;
typedef struct variable* variable_p;


/* the generic filter struct. If the filter has % then it means that it includes %r, or %u
 * and it needs parsing and substitution, in this case need_parsing is set to 1, otherwise
 * it is set to 0 */
struct filter_struct {
	char *filter;
	int need_parsing;
};

typedef struct filter_struct filter_struct;
typedef struct filter_struct* filter_struct_p;


/* The options struct that includes the different options that we support in the
 * configuration file  */
struct options {
	char *default_realm;
	filter_struct ldap_server;
	filter_struct base_dn;
	char *user_dn;
	char *manager_dn;
	char *manager_passwd;
	char *objectClass;
	filter_struct loginFilter;
	lista_p priority_rule;
	lista_p attributes;
};

typedef struct options options;
typedef struct options* options_p;

#define DEFAULT_CONFIG "/opt/OpenVPN/etc/auth_ldap.conf"

#include "user.h" /* XXX: This should NOT be here. Have to fix */
/*
 * Function Declares for Reading the configuration File
 */
int  read_config_file(const char *__fname, options_p __opt);
char *createuserDN(options_p __opt, auth_user_p __user);
char *createManagerDN(options_p __opt, auth_user_p __user);
char *createLdapHost(options_p __opt, auth_user_p __user);
char *createBaseDN(options_p __opt, auth_user_p __user);
char *createLoginFilter(options_p __opt, auth_user_p __user);
void free_options(options_p __opt);
/*static int fp_getline(FILE *__fp, char *__c);
static void fp_getline_init(char *__c);
static int fp_parse_line(char *__c);*/
#endif /* config.h */
