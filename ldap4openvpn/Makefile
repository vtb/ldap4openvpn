ifndef OPENVPN_SRC
OPENVPN_SRC=/SCRATCH/openvpn/UOAopenvpn.sources/openvpn-2.0.5/
endif
ifndef LDAP_INC
LDAP_INC=/usr/local/include
endif
ifndef LDAP_LIB
LDAP_LIB=/usr/local/lib
endif

LDFLAGS = -L$(LDAP_LIB) -lc -lldap -llber

ifeq ($(CC),gcc)
	CFLAGS=-g -fPIC -O2 -fno-strict-aliasing -pipe  -Wsystem-headers -Wall \
	    -Wno-format-y2k -W -Wno-unused-parameter -Wstrict-prototypes \
	    -Wmissing-prototypes -Wpointer-arith -Wreturn-type -Wcast-qual \
	    -Wwrite-strings -Wswitch -Wshadow -Wcast-align -Wunused-parameter \
	    -Wchar-subscripts -Winline -Wnested-externs -Wredundant-decls \
	    -I$(LDAP_INC) -I$(OPENVPN_SRC) -DLDAP_DEPRECATED -DMYMALLOC_DEBUG
else
# Solaris Required Flags
	CFLAGS = -g -xtarget=ultra2 -xarch=v8plusa -G -I$(OPENVPN_SRC) -I$(LDAP_INC) -DLDAP_DEPRECATED -DMYMALLOC_DEBUG
 	LDFLAGS += -xtarget=ultra2 -xarch=v8plusa -L/opt/SUNWconn/crypto/lib
endif

%.o : %.c
	$(CC)  -c $(CFLAGS) $< -o $@

all : openvpn

program : lista.o myldap.o config.o user.o main.o xmalloc.o auth_ldap.o
	$(CC) -o main *.o $(LDFLAGS)

openvpn: program
ifeq ($(CC),gcc)
	$(CC) -fPIC -shared -Wl,-soname,auth_ldap.so -o auth_ldap.so *.o $(LDFLAGS) -lc -lldap -llber
else	
	$(CC) -g -G -soname=auth_ldap.so -o auth_ldap.so *.o $(LDFLAGS) 
endif

program : lista.o myldap.o config.o user.o main.o xmalloc.o
clean:
	rm -rf *.o *.so main
