#ifndef SESSION_H
#define SESSION_H 1

#include <config.h>
#include <stdlib.h>

#endif /* SESSION_H */

int check_session(const char *assertion, char *email);

int create_session(const char *assertion, const char *email);
