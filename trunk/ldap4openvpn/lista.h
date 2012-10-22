#ifndef LISTA_H
#define LISTA_H

struct lista {
    char *key; // The key
    void *data; // The data
    struct lista *next;
};

typedef struct lista lista;
typedef struct lista * lista_p;



/* The functions that are defined in lista.c */
void addtolista (struct lista **__lista, void *__data, char *__key);
void deletefromlista(struct lista **__lista,char *__key);
void *findElement(struct lista *__lista, char *__key);

#endif /* lista.h */
