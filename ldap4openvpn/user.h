#ifndef USER_H
#define USER_H

#include "lista.h"
#include "config.h"

struct auth_user {
	char *name;
	char *realm;
	char *passwd;
	lista_p groups;
	lista_p dyn_groups;
	lista_p roles;
	lista_p dyn_roles;
};

typedef struct auth_user auth_user;
typedef struct auth_user* auth_user_p;

auth_user_p init_user(const char *__username, const char *__passwd, options_p __opt);
void free_user(auth_user_p __user);

#endif /* user.h */
	
