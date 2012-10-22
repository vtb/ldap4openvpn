#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>

#include "config.h"
#include "user.h"
#include "xmalloc.h"
#include <ctype.h>/*declare int tolower(int)*/

/*pre-defined buffer size*/
#define BUF_SIZE 512

/*functions which are needed for config file parsing*/
static char *my_getstring(char *__line, char **__str,int __delim);
static int my_getline(FILE *__fp,char **__buf);
static void string_tolower(char *__str);
static void options_constructor(options *opt);
/*end of functions which ...*/

static int replace(const char *filter, char **dest_p, auth_user_p user, char *objectClass, int place_len, int expand_realm);

// static variable_p variables; The array that holds the variables

/* Creates the ldap host, replacing the realm if it is needed */
char *
createLdapHost(options_p opt, auth_user_p user)
{
	char *ldap_host = NULL;
	int ldap_len = 0;

	if(!opt->ldap_server.need_parsing)
	{
		ldap_len+=strlen(opt->ldap_server.filter);
		XMALLOC(ldap_host, (ldap_len+1) * sizeof(char));
		strncpy(ldap_host, opt->ldap_server.filter, ldap_len);
		ldap_host[ldap_len] = '\0';
	}
	else {
		ldap_len = replace(opt->ldap_server.filter, &ldap_host, user, opt->objectClass, ldap_len, 0);
		if(ldap_len == -1) {
			FREE(ldap_host);
			ldap_host = NULL;
		}
	}
	return ldap_host;
}

/* Creates the user dn, using the base_dn and user_dn from options
 * and parsing them using the following conventions :
 * %u is replaced by the username
 * %r is replaced by the user realm.
 *   NOTE: The returned string should be freed by the calling function.
 */
char *
createuserDN(options_p opt, auth_user_p user)
{
	char *parsed_user_dn = NULL;
	int user_dn_len;
	
	user_dn_len = replace(opt->user_dn,&parsed_user_dn, user, opt->objectClass, 0, 0); 
	if(user_dn_len != -1 ) {
		user_dn_len++;
		XREALLOC(parsed_user_dn, user_dn_len+1);
		parsed_user_dn[user_dn_len - 1] = ',';
		parsed_user_dn[user_dn_len] = '\0';
		if(!opt->base_dn.need_parsing) {
			user_dn_len += strlen(opt->base_dn.filter);
			XREALLOC(parsed_user_dn, user_dn_len+1);
			strcat(parsed_user_dn, opt->base_dn.filter);
			parsed_user_dn[user_dn_len] = '\0';	
		} else 
			user_dn_len = replace(opt->base_dn.filter, &parsed_user_dn, user, opt->objectClass, user_dn_len, 1);
	}
	if(user_dn_len == -1) {
		FREE(parsed_user_dn);
		return NULL;
	} else
	return parsed_user_dn;
}


/* Creates the manager dn, using the base_dn and manager_dn from options
 * and parsing them using the following conventions :
 * %r is replaced by the user realm.
 *   NOTE: The returned string should be freed by the calling function.
 */
char *
createManagerDN(options_p opt, auth_user_p user)
{
	char *parsed_manager_dn = NULL;
	int manager_dn_len = 0;

	manager_dn_len = strlen(opt->manager_dn);
	manager_dn_len++;
	XMALLOC(parsed_manager_dn,(manager_dn_len+1)*sizeof(char));
	parsed_manager_dn = strncpy(parsed_manager_dn,opt->manager_dn, manager_dn_len);
	parsed_manager_dn[manager_dn_len - 1] = ',';
	parsed_manager_dn[manager_dn_len] = '\0'; /* This is not needed since strncpy copys the NUL, but for failsafe reasons */
	
	if(!opt->base_dn.need_parsing) {
		manager_dn_len += strlen(opt->base_dn.filter);
		XREALLOC(parsed_manager_dn, (manager_dn_len+1)*sizeof(char));
		strcat(parsed_manager_dn, opt->base_dn.filter);
		parsed_manager_dn[manager_dn_len] = '\0';	
	} else 
		manager_dn_len = replace(opt->base_dn.filter, &parsed_manager_dn, user, opt->objectClass, manager_dn_len, 1);
	if(manager_dn_len == -1) {
		FREE(parsed_manager_dn);
		return NULL;
	}

	return parsed_manager_dn;
}

char *
createBaseDN(options_p opt, auth_user_p user)
{
	char *parsed_base_dn = NULL;
	int base_dn_len = 0;

	if(!opt->base_dn.need_parsing) {
		base_dn_len += strlen(opt->base_dn.filter);
		XREALLOC(parsed_base_dn, (base_dn_len + 1)*sizeof(char));
		strncpy(parsed_base_dn, opt->base_dn.filter, base_dn_len);
		parsed_base_dn[base_dn_len] = '\0';
	}
	else {
		base_dn_len = replace(opt->base_dn.filter, &parsed_base_dn, user, opt->objectClass, base_dn_len, 0);
		if(base_dn_len == -1) {
			FREE(parsed_base_dn);
			parsed_base_dn = NULL;
		}
	}
	return parsed_base_dn;
}

char *
createLoginFilter(options_p opt, auth_user_p user)
{
	char *parsed_login_filter = NULL;
	int login_filter_len = 0;
	if(!opt->loginFilter.need_parsing) {
		login_filter_len += strlen(opt->loginFilter.filter);
		XREALLOC(parsed_login_filter, (login_filter_len+1)*sizeof(char));
		strncpy(parsed_login_filter,opt->loginFilter.filter,login_filter_len);
		parsed_login_filter[login_filter_len] = '/0';
	}
	else {
		login_filter_len = replace(opt->loginFilter.filter, &parsed_login_filter, user, opt->objectClass, login_filter_len,1);
		if(login_filter_len == -1) {
			FREE(parsed_login_filter);
			parsed_login_filter = NULL;
		}
	}
	return parsed_login_filter;
}

/* Gioyxoy .. Gn00keeee */
/* Method that replaces the %u, %r occurances on the filter with the corresponding parts in the auth_user structure 
 * of the %o with the objectClass that is used to see if the user has permission to use the vpn server
 * returns the lenght of the destination buffer  or -1 if there is an error 
 */
static int 
replace(const char *filter, char **dest_p, auth_user_p user, char *objectClass, int place_len, int expand_realm)
{

	char *dest = (*dest_p);
	const char *ptr = filter;
	char *ptr2, *ptr3, *ptr4 = NULL;
	int added_len = 0, i = 0;
	int len = place_len;

	assert(dest_p != NULL);
	assert(filter != NULL);

	while (ptr != NULL && *ptr != '\0') {
		ptr2 = strchr (ptr, '%');
		if(!ptr2) { /* the % doen't exist in the rest of filter */
			/* We copy the rest of the filter to the destination and return */
			added_len = strlen(ptr); 
			XREALLOC(dest, (len + added_len + 1)*sizeof(char));
			strncpy(dest+len*sizeof(char), ptr, added_len);
			len += added_len;
			dest[len] = '\0';
			*dest_p = dest;
			return len; /* return the length of the destination string */
		} else { /* we found a %, so we have to copy up to the % and then perform the replacement according to what was decided */
			added_len = ptr2 - ptr;
			XREALLOC(dest, (len + added_len +1)*sizeof(char));
			strncpy(dest + len*sizeof(char), ptr, added_len);
			len += added_len;
			dest[len] = '\0';	
			if(*(ptr2+1) == '\0') /* this means that the filter string is like: alfa%\0 which is wrong */
				return -1;
			switch(*(ptr2+1)) { /* Check the next character after ptr2 */
				case '%' : /* we just copy the % */
					len++; /* adding 1 */
					XREALLOC(dest,(len+1)*sizeof(char)); /* increasing the buffer */
					dest[len-1] = '%'; /* the copy */
					dest[len] = '\0'; /* NUL terminating as always ;) */
					ptr2 += 2; /* point to next place */
					break;
				case 'u' :
					added_len = strlen(user->name); 
					XREALLOC(dest, (len + added_len +1)*sizeof(char));
					strncpy(dest+len*sizeof(char), user->name, added_len); /* we could use strcat .. this is faster though */
					len += added_len;
					dest[len] = '\0'; /* NUL terminated . Perhaps we could avoid it .. but better have it there */
					ptr2+=2;
					break;
				case 'r' :
					ptr3 = user->realm; /* pointer to the realm */
					if(!ptr3) /* This is the case that the admin has requested a realm replacing but the user has set up no realm
						   * and the admin hasn't setup a default_realm. This is an error */
						return -1;
					if(expand_realm) /* If we want to expand the realm */
						for(ptr4 = ptr2; *ptr4 != ',' && i <= len ; ptr4-- , i++); /* Finding the , or the beggining if %r is the first element */
					do {
						while(*ptr3 != '\0' && *ptr3 != '.') { /* copy the chars until the realm finished or we find a . */
							len++;
							XREALLOC(dest, (len+1)*sizeof(char));
							dest[len-1] = *ptr3;
							dest[len] = '\0';
							ptr3++;
						}
						if(*ptr3 != '\0') { /* if ptr3 points to . then increase to get the next element */
							if(expand_realm) {
								added_len = (ptr2 - ptr4); /* copy the part that has to be repeated */
								XREALLOC(dest, (len + added_len +1)*sizeof(char));
								strncpy(dest+len*sizeof(char), ptr4,added_len);
								len += added_len;
								dest[len] = '\0';
							}
							else {
								len++;
								XREALLOC(dest, (len+1)*sizeof(char));
								dest[len-1] = *ptr3;
								dest[len] = '\0';
							}
							ptr3++;
						}
					} while(*ptr3 != '\0');
					ptr2 += 2;
					break;
				case 'o' :
					if(!objectClass) /*this is the case that the admin requested an objectclass replacement but didn't initiate the option variable */
						return -1;
					added_len = strlen(objectClass);
					XREALLOC(dest,(len+added_len+1)*sizeof(char));
					strncpy(dest+len*sizeof(char), objectClass, added_len);
					len+=added_len;
					dest[len] = '\0';
					ptr2+=2;
					break;
				default: 
					/* Something wrong exists in the filter string. return -1 to report the error */
					return -1;
			}
					
		}
		ptr = ptr2; /* we set the ptr to ptr2 so to continue for the next replacement */
	} 
	*dest_p = dest;
	return len;
}

void 
free_options(options_p opt) 
{
	lista_p iterator = NULL, previous = NULL;

	assert(opt != NULL);

	if(opt->default_realm)
		FREE(opt->default_realm);
	if(opt->ldap_server.filter) 
		FREE(opt->ldap_server.filter);
	if(opt->base_dn.filter)
		FREE(opt->base_dn.filter);
	if(opt->loginFilter.filter)
		FREE(opt->loginFilter.filter);
	if(opt->user_dn)
		FREE(opt->user_dn);
	if(opt->manager_dn)
		FREE(opt->manager_dn);
	if(opt->manager_passwd)
		FREE(opt->manager_passwd);
	if(opt->objectClass)
		FREE(opt->objectClass);
	if(opt->priority_rule) {
		iterator = opt->priority_rule;
		while(iterator != NULL) {
			FREE(iterator->key);
			FREE(iterator->data);
			previous = iterator;
			iterator = iterator->next;
			FREE(previous);
		}
	}
	if(opt->attributes) {
		iterator = opt->attributes;
		while(iterator != NULL) {
			FREE(iterator->key);
			FREE(iterator->data);
			previous = iterator;
			iterator = iterator->next;
			FREE(previous);
		}
	}
	FREE(opt);
}


/*
 *initialize struct options object( and its member data)
 */
static void 
options_constructor(options *opt){
        (*opt).default_realm=NULL;        
        (*opt).ldap_server.filter=NULL;
        (*opt).base_dn.filter=NULL;
        (*opt).loginFilter.filter=NULL;
        (*opt).user_dn=NULL;        
        (*opt).manager_dn=NULL;        
        (*opt).manager_passwd=NULL;        
        (*opt).objectClass=NULL;        
        (*opt).attributes=NULL;        
        (*opt).priority_rule=NULL;        
}


/*
 *change all <str> characters to lower
 */
static void 
string_tolower(char *str){
        
        while (*str!='\0'){
                *str=tolower(*str);
                str++;
        }
}

int
read_config_file(const char *fname,options *opt)
{
	struct stat s;
	FILE *fp;
        char *line=NULL;
	char *tmp=NULL;
	char *token=NULL;
	char *data_token1=NULL;
	char *data_token2=NULL;
        int num_bytes;

        /*1*/
        options_constructor(opt);/*initialize members of opt object*/

        /*2*/
        if ( stat( fname, &s ) != 0 ) {
                 printf("could not stat config file \"%s\": %s (%d)\n",fname, strerror(errno), errno);
                return 1;
        }
        if ( !S_ISREG( s.st_mode ) ) {
                printf("regular file expected, got \"%s\"\n",fname);
                return 1;
        }

        /*3*/
        fp = fopen( fname, "r" );
        if ( fp == NULL ) {
        /*
         * Currently just exit
         * just print an error and exit
         */
                printf("could not open config file \"%s\": %s (%d)\n",fname, strerror(errno), errno);
                return 1;
        }

        /*main body*/
        while(!feof(fp))
        {
                num_bytes=my_getline(fp, &line);	/*line is malloced into my_getline function.Thus we have to free it later*/
                tmp=line;       /*I need it, to be capable to free malloced memory to the end. Otherwhise, memory leak*/


                tmp=(char *)my_getstring(tmp, &token, ':');
                if (tmp == NULL) {
			FREE(line);
			line = tmp = NULL;
                        continue;
		}

                 /*update <option> structure*/
                 string_tolower(token);
                 if (strcmp("default_realm",token) == 0)
                 {
                        if ((tmp = my_getstring(tmp,&data_token1,':')) != NULL)
                                 opt->default_realm=data_token1;
                 }
                 else if (strcmp("user_dn",token) == 0)
                 {
                        if ((tmp = my_getstring(tmp,&data_token1,':')) != NULL)
                                opt->user_dn=data_token1;
                }
                else if (strcmp("manager_dn",token) == 0)
                {
                        if ((tmp = my_getstring(tmp,&data_token1,':')) != NULL)
                                opt->manager_dn=data_token1;
                }
                else if (strcmp("manager_passwd",token) == 0)
                {
                        if ((tmp = my_getstring(tmp,&data_token1,':')) != NULL)
                                opt->manager_passwd=data_token1;
                }
                else if (strcmp("objectclass",token) == 0)
                {
                        if ((tmp = my_getstring(tmp,&data_token1,':')) != NULL)
                                opt->objectClass=data_token1;
                }
                else if (strcmp("loginfilter",token) == 0)
                {
                        if ((tmp = my_getstring(tmp,&data_token1,':')) != NULL)
                        {
                                opt->loginFilter.filter=data_token1;
                                if (strstr((opt->loginFilter).filter, "%") != NULL)
                                        opt->loginFilter.need_parsing=1;
                                else
                                        opt->loginFilter.need_parsing=0;
                        }
                }
                else if (strcmp("ldap_server",token) == 0)
                {
                        if ((tmp = my_getstring(tmp,&data_token1,':')) != NULL)
                        {
                                opt->ldap_server.filter=data_token1;
                                if (strstr((opt->ldap_server).filter, "%") != NULL)
                                        opt->ldap_server.need_parsing=1;
                                else
                                        opt->ldap_server.need_parsing=0;
                        }
                }
                else if (strcmp("base_dn",token) == 0)
                {
                        if ((tmp = my_getstring(tmp,&data_token1,':')) != NULL)
                        {
                                opt->base_dn.filter=data_token1;
                                if (strstr((opt->base_dn).filter, "%") != NULL)
                                        opt->base_dn.need_parsing=1;
                                else
                                        opt->base_dn.need_parsing=0;
                        }
                }
                else if (strcmp("priority_rule",token)  == 0)
                {
                        /*
                        *auto to xazo kommati kwdika mphke gia na petaksw to ':', pou sigoura uparxei, apo th line
                        *dedomenou oti to delimeter allazei mesa se auto to loop den brhka allo tropo na to kanw
                        *pisteuw oti oi pio katw grammes prepei me kapoio tropo na ginoun pio eksupna
                        */
                        while (*tmp != ':')
                                tmp++;
                        tmp++;
                        while ( (tmp=my_getstring(tmp,&data_token1,'|')) != NULL)
                                addtolista(&opt->priority_rule,NULL,data_token1);     /*(NULL,key==rule)*/
                }
                else if (strcmp("attributes",token) == 0)
                {
                        if ( ((tmp = my_getstring(tmp,&data_token1,':')) == NULL)|| ((tmp = my_getstring(tmp,&data_token2,':')) == NULL))
                        {
                                if (data_token1!=NULL){
                                        FREE(data_token1);
                                        data_token1=NULL;
                                }
                                if (data_token2!=NULL){
                                        FREE(data_token2);
                                        data_token2=NULL;
                                }
                                fprintf(stderr,"warning: Line is ignored because attributes fields can not be empty\n");
                        }
                        else{
                                addtolista(&opt->attributes,(void *)data_token2,data_token1);//(data,key)
                        }
                }
                else
                {
                        fprintf(stderr,"warning: Option <%s> is ignored because can not be recognised\n",token);
                }

		if (token)
		{
			FREE(token);
			token=NULL;
		}
		if (line!=NULL)
		{
			FREE(line);
			line=NULL;
			tmp=NULL;
		}
        }
        fclose(fp);
	fp=NULL;
	
return 0;
}

static int
my_getline(FILE *fp, char **buff)
{
        char *tmp=NULL;
        char ch;
        int i=0;

        /*Initialize the buffer we are going to store new line*/
	XMALLOC(*buff, BUF_SIZE * sizeof(char));
	i++;

        /*main body*/
        tmp=*buff;
        while( ((ch=fgetc(fp))!=EOF) && (ch!='\n') )
        {
                if (tmp - (*buff) >= BUF_SIZE)
                {
                        XREALLOC(tmp,(i * BUF_SIZE + BUF_SIZE) * sizeof(char));
                        i++;
                }
                *tmp++=ch;
        }

        *tmp++='\0';
        return (tmp - *buff);    /*if tmp - *buff == 1, then */
}

static char *
my_getstring(char *line, char **str, int delimeter)    /*delimeter= ':' or  '|'*/
{
        char *start_p=NULL;
        char *end_p=NULL;

        /*main body*/
        while ((*line == ' ') || (*line == '\t'))       /*ignore all white spaces from the beggining of the line*/
                line++;


        if (*line == '\0')      /*return NULL, if line is empty*/
                return NULL;

        if ((*line == ';') || (*line == '#'))   /*return NULL, if line is comment*/
                return NULL;

        if (*line == delimeter)
        {
                line++;
                while ((*line == ' ') || (*line == '\t'))
                        line++;
                if (*line == delimeter)         /*return NULL, if "::" or "||" or ":    :" or "|     |"*/
                        return NULL;
                while ((*line == ' ') || (*line == '\t'))
                        line++;
        }

        /*find the start_p and the end_p of the string*/
        for (start_p=line, end_p=line; (*line != delimeter) && (*line != ' ') && (*line != '\t') && (*line != '\0'); line++)
                end_p=line;

        /*malloc needed memory, initialize it to zero and copy string there*/
        XMALLOC(*str,end_p - start_p + 2);
        bzero(*str,end_p - start_p + 2);
        strncpy(*str,start_p,end_p - start_p + 1);

        return line;    /*New position of line*/
}


#ifdef DEBUG
/*
int main (void) 
{
	char *parsed_uid;
	options my_options;
	auth_user myauthuser;

	my_options.base_dn.filter = ",ou=People, dc=%r";
	my_options.base_dn.need_parsing = 1;
	my_options.user_dn = "uid=%u@%r";

	myauthuser.name = "arisg";
	myauthuser.realm = "uoa.gr";

	parsed_uid = createuserDN(&my_options,&myauthuser);

	printf("%s\n",parsed_uid);

	return 0;
}
*/
#endif /* DEBUG */
