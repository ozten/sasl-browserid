#ifndef VERIFIER_H
#define VERIFIER_H 1

#include <config.h>

#include <stdlib.h>

#include <sasl/sasl.h> /* saslplug.h should have included this ?!? */
#include <sasl/saslplug.h>

#include "yajl/yajl_parse.h"
#include "yajl/yajl_tree.h"

#define MAX_STATUS 64
#define MAX_RESP_FIELD 1024

struct browserid_response_t {
	char status[MAX_STATUS]; /* "okay" */
	char email[MAX_RESP_FIELD]; /* shout@ozten.com */
	char audience[MAX_RESP_FIELD]; /* mozillians.org */
	long long expires; /* timeout */
	char issuer[MAX_RESP_FIELD]; /* browserid.org:443 */
	char reason[MAX_RESP_FIELD]; /* Set if status is failure */
};

/**
 * Uses the BrowserID webservice to verify an identity assertion
 * for a given audience. Returns a browserid_response_t.
 */
int browserid_verify(const sasl_utils_t *utils, struct browserid_response_t *browserid_response, const char *assertion, const char *audience);

#endif /* VERIFIER_H */
