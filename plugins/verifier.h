#ifndef VERIFIER_H
#define VERIFIER_H 1

#include <config.h>

#include <stdlib.h>

#include <sasl/sasl.h> /* saslplug.h should have included this ?!? */
#include <sasl/saslplug.h>

#include "yajl/yajl_parse.h"
#include "yajl/yajl_tree.h"

struct browserid_response_t {
  char state[64];
  char status[64]; /* "okay" */
  char email[1024]; /* shout@ozten.com */
  char audience[1024]; /* mozillians.org */
  long long valid_until; /* timeout */
  char issuer[1024]; /* browserid.org:443 */
  char reason[1024]; /* Set if status is failure */
};

/**
 * Uses the BrowserID webservice to verify an identity assertion
 * for a given audience. Returns a browserid_response_t.
 */
int browserid_verify(const sasl_utils_t *utils, struct browserid_response_t *browserid_response, const char *assertion, const char *audience);

#endif /* VERIFIER_H */
