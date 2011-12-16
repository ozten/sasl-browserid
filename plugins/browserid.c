/* BROWSER-ID SASL plugin
 * $Id: browserid.c,v 1.180 2006/04/26 17:39:26 mel Exp $
 *
 * A Cyrus SASL Auth Mechanism for BrowserID.
 *
 * This plugin implements both the client and server code.
 *
 * A typical senario would be Python ldap code loading the client
 * plugin and then a slapd LDAP server loading the server plugin.
 *
 * Clients should make sure assertion and audience are present in the request.
 *
 * See http://github.com/mozilla/sasl-browserid for details
 *
 * References:
 * * http://cyrusimap.web.cmu.edu/docs/cyrus-sasl/2.1.23/plugprog.php
 *
 */
#include <config.h>

#include <error.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifndef macintosh
#include <sys/types.h>
#include <sys/stat.h>
#endif
#include <fcntl.h>
#include <ctype.h>

#include <sasl.h>
#include <saslplug.h>

#include "plugin_common.h"

#ifdef macintosh
#include <sasl_broserid_plugin_decl.h>
#endif

#include <unistd.h>

#include <session.h>
#include <verifier.h>

/* MAX_ASSERTION length which BrowserID generates */
#define MAX_ASSERTION 4000

/* MAX_AUDIENCE 256 for protocol, domain nam, and padding for port number */
#define MAX_AUDIENCE 300

/* MAX_EMAIL length */
#define MAX_EMAIL 254

static const char plugin_id[] = "$Id: browserid.c,v 1.180 2011/08/11 17:00:00 mel Exp $";

static const unsigned short version = 5;

/*****************************	Common Section	*****************************/

/**
 * Application is shutting down. Your FREE, FREE!
 */
static void browserid_common_mech_free(void *glob_context,
				       const sasl_utils_t *utils)
{
	utils->log(NULL, SASL_LOG_DEBUG, "browserid_common_mech_free");
	return;
}

/*****************************	Server Section	*****************************/

/**
 * Called at the start of a new connection. conn_context will persist
 * throught the request. Doesn't send any data to the server.
 */
static int browserid_server_mech_new(void *glob_context,
				     sasl_server_params_t * sparams,
				     const char *challenge __attribute__((unused)),
				     unsigned challen __attribute__((unused)),
				     void **conn_context)
{
	sparams->utils->log(NULL, SASL_LOG_DEBUG, "browserid_server_mech_new");
	return SASL_OK;
}

static int _transmit_email(sasl_server_params_t *sparams,
			   const char **serverout,
			   unsigned *serveroutlen,
			   char *email)
{
	*serveroutlen = strlen(email);
	*serverout = sparams->utils->malloc(*serveroutlen + 1);
	if (*serverout == NULL) {
		MEMERROR(sparams->utils);
		return SASL_NOMEM;
	}
	strcpy(*serverout, email);
	sparams->utils->log(NULL, SASL_LOG_DEBUG, "Sending [%s] back to client", *serverout);
	return SASL_OK;
}


/**
 * Core of the server plugin.
 */
static int browserid_server_mech_step(void *conn_context,
				      sasl_server_params_t *sparams,
				      const char *clientin,
				      unsigned clientinlen,
				      const char **serverout,
				      unsigned *serveroutlen,
				      sasl_out_params_t *oparams)
{
	const char *assertion;
	const char *audience;
	unsigned audience_len;
	unsigned lup=0;
	int result;
	char *audience_copy;
	struct browserid_response_t *browserid_response;
	char email[MAX_EMAIL];

	sparams->utils->log(NULL, SASL_LOG_DEBUG, "browserid_server_mech_step clientinlen=%d",
	       clientinlen);

	/* should have received assertion NUL audience */

	/* get assertion */

	assertion = clientin;

	if (strlen(assertion) > MAX_ASSERTION) {
		sparams->utils->log(NULL, SASL_LOG_ERR, "Client send a longer assertion [%u] that we "
		       "expected, failing", strlen(assertion));
		return SASL_BADPROT;
	}

	sparams->utils->log(NULL, SASL_LOG_DEBUG, "Assertion: [%s]", assertion);

	while ((lup < clientinlen) && (clientin[lup] != 0)) ++lup;

	if (lup >= clientinlen) {
		SETERROR(sparams->utils, "Can only find browserid assertion "
			 "(no audience)");
		return SASL_BADPROT;
	}

	/* get audience */
	++lup;
	audience = clientin + lup;
	while ((lup < clientinlen) && (clientin[lup] != 0)) ++lup;

	audience_len = (unsigned) (clientin + lup - audience);
	if (audience_len > MAX_AUDIENCE) {
	    sparams->utils->log(NULL, SASL_LOG_ERR, "Client send a longer audience [%u] that "
		   "we expected, failing",
		   strlen(audience));
		return SASL_BADPROT;
	}
	sparams->utils->log(NULL, SASL_LOG_DEBUG, "lup = %d clientinlen = %d", lup,
	       clientinlen);

	++lup;
	if (lup != clientinlen) {
		SETERROR(sparams->utils,
			 "Client sent more data than the two fields we were expecting");
		return SASL_BADPROT;
	}

	/* Ensure null terminated */
	audience_copy = sparams->utils->malloc(audience_len + 1);
	if (audience_copy == NULL) {
		MEMERROR(sparams->utils);
		return SASL_NOMEM;
	}

	strncpy(audience_copy, audience, audience_len);
	audience_copy[audience_len] = '\0';

	sparams->utils->log(NULL, SASL_LOG_DEBUG, "Server side, we've got AUDIENCE[%s] ASSERTION[%s]",
	       audience_copy, assertion);

	if (check_session(sparams->utils, assertion, (char *)&email) == 1) {
		sparams->utils->log(NULL, SASL_LOG_DEBUG, "Found email = %s in session", email);
		/* set user into the session or whatever... */
		result = sparams->canon_user(sparams->utils->conn,
					     email, 0,
					     SASL_CU_AUTHID | SASL_CU_AUTHZID,
					     oparams);
		_transmit_email(sparams, serverout, serveroutlen, email);
	} else {
		sparams->utils->log(NULL, SASL_LOG_DEBUG, "No session hit, using verifier");
		browserid_response = malloc(sizeof(struct browserid_response_t));
		if (browserid_response == NULL) {
			MEMERROR(sparams->utils);
			return SASL_NOMEM;
		}

		result = browserid_verify(sparams->utils, browserid_response,
					  assertion, audience_copy);
		if (result != SASL_OK) {
		    return result;
		}

		if (strcasecmp(browserid_response->status, "okay") == 0) {
			sparams->utils->log(NULL, SASL_LOG_DEBUG, "Yes, we're all good! %s %s %s until %llu",
			       browserid_response->email,
			       browserid_response->audience,
			       browserid_response->issuer,
			       browserid_response->expires);

			if (strcasecmp(browserid_response->audience, audience_copy) != 0) {
			    sparams->utils->log(NULL, SASL_LOG_ERR, "BAD Audience, expected [%s] != [%s]",
				   audience_copy, browserid_response->audience);
			    return SASL_BADAUTH;
			}

			create_session(sparams->utils, assertion,
				       browserid_response->email);
			result = sparams->canon_user(sparams->utils->conn,
						     browserid_response->email, 0,
						     SASL_CU_AUTHID | SASL_CU_AUTHZID,
						     oparams);

			_transmit_email(sparams, serverout, serveroutlen, browserid_response->email);

			if (result != SASL_OK) {
				_plug_free_string(sparams->utils, &audience_copy);
				free(browserid_response);
				return result;
			}

		} else {
			sparams->utils->log(NULL, SASL_LOG_ERR, "No dice, STATUS=[%s] REASON=[%s]",
			       browserid_response->status,
			       browserid_response->reason);
			SETERROR(sparams->utils, browserid_response->reason);

			_plug_free_string(sparams->utils, &audience_copy);
			free(browserid_response);
			return SASL_BADAUTH;
		}

		free(browserid_response);
	}
	_plug_free_string(sparams->utils, &audience_copy);


	/* set oparams */
	oparams->doneflag = 1;
	oparams->mech_ssf = 0;
	oparams->maxoutbuf = 0;
	oparams->encode_context = NULL;
	oparams->encode = NULL;
	oparams->decode_context = NULL;
	oparams->decode = NULL;
	oparams->param_version = 0;
	return SASL_OK;
}

/**
 * This request is over, connection coming to an end.
 */
static void browserid_server_mech_dispose(void *conn_context,
					  const sasl_utils_t *utils)
{
	utils->log(NULL, SASL_LOG_DEBUG, "browserid_server_mech_dispose");
	return;
}

static sasl_server_plug_t browserid_server_plugins[] =
{
    {
	"BROWSER-ID",			/* mech_name */
	1,				/* TODO max_ssf */
	SASL_SEC_NOPLAINTEXT
	| SASL_SEC_NOANONYMOUS
	| SASL_SEC_MUTUAL_AUTH,		/* security_flags */
	SASL_FEAT_ALLOWS_PROXY,		/* features */
	NULL,				/* glob_context */
	&browserid_server_mech_new,	/* mech_new */
	&browserid_server_mech_step,	/* mech_step */
	&browserid_server_mech_dispose,	/* mech_dispose */
	&browserid_common_mech_free,	/* mech_free */
	NULL,				/* setpass */
	NULL,				/* user_query */
	NULL,				/* idle */
	NULL,				/* mech avail */
	NULL				/* spare */
    }
};

int browserid_server_plug_init(sasl_utils_t *utils,
			       int maxversion,
			       int *out_version,
			       sasl_server_plug_t **pluglist,
			       int *plugcount)
{
	utils->log(NULL, SASL_LOG_DEBUG, "browserid_server_plug_init");
	if (maxversion < SASL_SERVER_PLUG_VERSION) {
		SETERROR( utils, "ANONYMOUS version mismatch" );
		return SASL_BADVERS;
	}

	*out_version = SASL_SERVER_PLUG_VERSION;
	*pluglist = browserid_server_plugins;
	*plugcount = 1;
	return SASL_OK;
}

/*****************************	Client Section	*****************************/

typedef struct client_context {
	int state;
	char *out_buf;
	unsigned out_buf_len;
} client_context_t;

/**
 * Called at the beginning of each connection. conn_context will exist
 * throught the client lifecycle. Doesn't send any data to the client.
 */
static int browserid_client_mech_new(void *glob_context,
				     sasl_client_params_t * params,
				     void **conn_context)
{
	params->utils->log(NULL, SASL_LOG_DEBUG, "browserid_client_mech_new");
	client_context_t *context;

	context = params->utils->malloc(sizeof(client_context_t));
	if (context == NULL) {
		MEMERROR( params->utils );
		return SASL_NOMEM;
	}

	memset(context, 0, sizeof(client_context_t));
	context->state = 1;
	*conn_context = context;
	return SASL_OK;
}

/**
 * Figure out the user's assertion and audience then send to the server.
 */
static int browserid_client_mech_step1(void *conn_context,
				      sasl_client_params_t *params,
				      const char *serverin,
				      unsigned serverinlen,
				      sasl_interact_t **prompt_need,
				      const char **clientout,
				      unsigned *clientoutlen,
				      sasl_out_params_t *oparams)
{
	client_context_t *context = (client_context_t *) conn_context;
	const char *browser_assertion = NULL, *browser_audience = NULL;
	int browser_assertion_result = SASL_OK;
	int browser_audience_result = SASL_OK;
	int result;
	char *p;

	params->utils->log(NULL, SASL_LOG_DEBUG, "browserid_client_mech_step1");

	if (!params || !clientout || !clientoutlen || !oparams) {
		PARAMERROR( params->utils );
		return SASL_BADPARAM;
	}

	/* try to get the assertion */
	if (oparams->authid == NULL) {
		/* TODO get_authid should be get_assertion */
		browser_assertion_result = _plug_get_userid(params->utils,
							    &browser_assertion,
							    prompt_need);

		if ((browser_assertion_result != SASL_OK) && \
		    (browser_assertion_result != SASL_INTERACT)) {
			return browser_assertion_result;
		}


	}

	/* try to get the audience */
	if (oparams->user == NULL) {
		/* TODO get_authid should be get_audience */
		browser_audience_result = _plug_get_authid(params->utils, &browser_audience, prompt_need);

		if ((browser_audience_result != SASL_OK) && \
		    (browser_audience_result != SASL_INTERACT)) {
			return browser_audience_result;
		}

	}

	/* free prompts we got */
	if (prompt_need && *prompt_need) {
		params->utils->free(*prompt_need);
		*prompt_need = NULL;
	}

	/* if there are prompts not filled in */
	if ((browser_audience_result == SASL_INTERACT) || \
	    (browser_assertion_result == SASL_INTERACT)) {
		/* make the prompt list, hijack user and auth slots */
		result =
		    _plug_make_prompts(params->utils, prompt_need,
				       browser_assertion_result == SASL_INTERACT ?
				       "Please enter your assertion" : NULL,
				       NULL,
				       browser_audience_result == SASL_INTERACT ?
				       "Please enter your interwebs (example.com)" : NULL,
				       NULL,
				       /* pass prompt, default */
				       NULL, NULL,
				       /* echo challange, prompt, default */
				       NULL, NULL, NULL,
				       /* realm challange, prompt, default */
				       NULL, NULL, NULL);
		if (result != SASL_OK) goto cleanup;
		return SASL_INTERACT;
	}
	if (strlen(browser_assertion) == 0) {
		params->utils->log(NULL, SASL_LOG_ERR, "browser_assertion is empty, failing");
		return SASL_BADPARAM;
	}
	if (strlen(browser_assertion) > MAX_ASSERTION) {
		params->utils->log(NULL, SASL_LOG_ERR, "browser_assertion is larger than we expected "
		       "(%u), failing", strlen(browser_assertion));
		return SASL_BADPARAM;
	}
	if (strlen(browser_audience) == 0) {
		params->utils->log(NULL, SASL_LOG_ERR, "browser_audience is empty, failing");
		return SASL_BADPARAM;
	}
	if (strlen(browser_audience) > MAX_AUDIENCE) {
		params->utils->log(NULL, SASL_LOG_ERR, "browser_audience is larger than we expected "
		       "(%u), failing", strlen(browser_audience));
		return SASL_BADPARAM;
	}
	params->utils->log(NULL, SASL_LOG_DEBUG, "YO ASSERTION=[%s] AUDIENCE=[%s]",
	       browser_assertion, browser_audience);

	/* send assertion NUL audience NUL */
	*clientoutlen = (strlen(browser_assertion) + 1 + strlen(browser_audience) + 1);

	params->utils->log(NULL, SASL_LOG_DEBUG, "clientoutlen is going to be %u", *clientoutlen);

	result = _plug_buf_alloc(params->utils, &(context->out_buf),
				 &(context->out_buf_len), *clientoutlen);
	if (result != SASL_OK) goto cleanup;

	memset(context->out_buf, 0, *clientoutlen);

	p = params->utils->malloc(*clientoutlen);
	if (p == NULL) {
		MEMERROR( params->utils );
		return SASL_NOMEM;
	}

	strcpy(p, browser_assertion);
	p += strlen(browser_assertion) + 1;
	strcpy(p, browser_audience);
	p -= strlen(browser_assertion) + 1;
	*clientout = p;

	context->state = 2;
	return SASL_CONTINUE;

 cleanup:
	return result;
}

/**
 * Read email address from server and canonicalize the userid and authname.
 */
static int browserid_client_mech_step2(void *conn_context,
				      sasl_client_params_t *params,
				      const char *serverin,
				      unsigned serverinlen,
				      sasl_interact_t **prompt_need,
				      const char **clientout,
				      unsigned *clientoutlen,
				      sasl_out_params_t *oparams)
{
	client_context_t *context = (client_context_t *) conn_context;
	char *email;
	int result;

	params->utils->log(NULL, SASL_LOG_DEBUG, "browserid_client_mech_step2 serverinlen=%d", serverinlen);

	/* should have received email NUL */
	email = serverin;

	if (strlen(email) > MAX_EMAIL) {
		params->utils->log(NULL, SASL_LOG_ERR, "Server sent a longer email [%u] that we "
		       "expected, failing", strlen(email));
		return SASL_BADPROT;
	}

	params->utils->log(NULL, SASL_LOG_DEBUG, "client step2 seeing email=[%s]", email);

	result = params->canon_user(params->utils->conn, email, 0,
			   SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams);

	if (result != SASL_OK) goto cleanup;

	oparams->doneflag = 1;
	oparams->mech_ssf = 0;
	oparams->maxoutbuf = 0;
	oparams->encode_context = NULL;
	oparams->encode = NULL;
	oparams->decode_context = NULL;
	oparams->decode = NULL;
	oparams->param_version = 0;

 cleanup:
	return result;
}
/**
 * Core of the client plugin. Does client side authentication... which
 * is none. Probably we need a two step where we get the server
 * to figure out the hard stuff.
 */
static int browserid_client_mech_step(void *conn_context,
				      sasl_client_params_t *params,
				      const char *serverin,
				      unsigned serverinlen,
				      sasl_interact_t **prompt_need,
				      const char **clientout,
				      unsigned *clientoutlen,
				      sasl_out_params_t *oparams)
{
	client_context_t *context = (client_context_t *) conn_context;
	switch (context->state) {
		case 1:
			return browserid_client_mech_step1(conn_context,
							  params,
							  serverin,
							  serverinlen,
							  prompt_need,
							  clientout,
							  clientoutlen,
							  oparams);
		case 2:
			return browserid_client_mech_step2(conn_context,
							  params,
							  serverin,
							  serverinlen,
							  prompt_need,
							  clientout,
							  clientoutlen,
							  oparams);
		default:
			params->utils->log(NULL, SASL_LOG_ERR, "Unknown state in client step %d", context->state);
			return SASL_BADPARAM;
	}
}

/**
 * Client side connection is no longer in use.
 */
static void browserid_client_mech_dispose(void *conn_context,
					  const sasl_utils_t *utils)
{
	utils->log(NULL, SASL_LOG_DEBUG, "browserid_client_mech_dispose");

	client_context_t *context = (client_context_t *) conn_context;

	if (!context) return;

	if (context->out_buf) utils->free(context->out_buf);

	utils->free(context);

	return;
}

static sasl_client_plug_t browserid_client_plugins[] =
{
    {
	"BROWSER-ID",
	1,				/* TODO... max_ssf */
	SASL_SEC_NOPLAINTEXT
	| SASL_SEC_NOANONYMOUS
	| SASL_SEC_MUTUAL_AUTH,		/* security_flags */
	SASL_FEAT_NEEDSERVERFQDN
	| SASL_FEAT_ALLOWS_PROXY,	/* features */
	NULL,				/* required_prompts */
	NULL,				/* glob_context */
	&browserid_client_mech_new,	/* mech_new */
	&browserid_client_mech_step,	/* mech_step */
	&browserid_client_mech_dispose,	/* mech_dispose */
	&browserid_common_mech_free,	/* mech_free */
	NULL,				/* idle */
	NULL,				/* spare1 */
	NULL				/* spare2 */
    }
};

int browserid_client_plug_init(sasl_utils_t *utils,
			       int maxversion,
			       int *out_version,
			       sasl_client_plug_t **pluglist,
			       int *plugcount)
{
	utils->log(NULL, SASL_LOG_ERR, "browserid_client_plug_init_plugin initialized");
	if (maxversion < SASL_CLIENT_PLUG_VERSION) {
		SETERROR( utils, "ANONYMOUS version mismatch" );
		return SASL_BADVERS;
	}

	*out_version = SASL_CLIENT_PLUG_VERSION;
	*pluglist = browserid_client_plugins;
	*plugcount = 1;
	return SASL_OK;
}
