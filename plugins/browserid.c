/* BROWSER-ID SASL plugin
 * $Id: browserid.c,v 1.180 2006/04/26 17:39:26 mel Exp $
 *
 * A Cyrus SASL Mechanism plugin for using browserid.org authentication.
 * 
 * This plugin implements a client and server side.
 * A typical senario would be Python ldap code loading the client
 * plugin and then a slapd LDAP server loading the server plugin.
 *
 * Client makes sure assertion and audience are present in the request.
 *
 * References:
 * * http://cyrusimap.web.cmu.edu/docs/cyrus-sasl/2.1.23/plugprog.php
 *
 */

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
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

#include <curl/curl.h>

#include "yajl/yajl_parse.h"
#include "yajl/yajl_tree.h"

struct json_ctx_t {
  char state[64];
  char status[64]; /* "okay" */
  char email[1024]; /* shout@ozten.com */
  char audience[1024]; /* mozillians.org */
  /* long valid_until; timeout */
  char issuer[1024]; /* browserid.org:443 */
  char reason[1024]; /* Set if status is failure */
};

#define bool int

#ifndef TRUE
#define TRUE  (1)
#define FALSE (0)
#endif

/* MAX_UIN32_DIV_10 * 10 + MAX_UIN32_MOD_10 == 2^32-1 == 4294967295 */
#define MAX_UIN32_DIV_10    429496729
#define MAX_UIN32_MOD_10    5

#define DEFAULT_BUFSIZE	    0xFFFF
#define MAX_SASL_BUFSIZE    0xFFFFFF

/***************************** BrowserID Section ****************************/
/* yajl callback functions */
static int json_string(void *ctx, const unsigned char *ukey, size_t len)
{
  struct json_ctx_t *parser = ctx;
  const char *key = parser->state;
  const char *val = strndup(ukey, len);
  syslog(LOG_DEBUG, "json_string %s=%s", key, val);

  if (strcasecmp(key, "status") == 0) {
    strncpy(parser->status, ukey, len);
    syslog(LOG_DEBUG, "status=%s", parser->status);
  } else if (strcasecmp(key, "email") == 0) {
    strncpy(parser->email, ukey, len);
    syslog(LOG_DEBUG, "email=%s", val);
  } else if (strcasecmp(key, "audience") == 0) {
    strncpy(parser->audience, ukey, len);
    syslog(LOG_DEBUG, "audience = %s", val);
  } else if (strcasecmp(key, "issuer") == 0) {
    strncpy(parser->issuer, ukey, len);
    syslog(LOG_DEBUG, "issuer=%s", val);
  } else if (strcasecmp(key, "reason") == 0) {
    strncpy(parser->reason, ukey, len);
    syslog(LOG_DEBUG, "reason=%s", val);
  } else {
    syslog(LOG_DEBUG, "unknown json_string=%s", key);
  }
  /* valid-until => json_number */

  /*
    if (strcmp(parser->curkey, "type") == 0 &&
        strncmp(key, "error", 5) == 0) {
        return 1;
    } else if (strcmp(parser->curkey, "ID") == 0) {
  */
  /*parser->curpkg->id = strndup(key, len);*/
  /*}*/

  return 1;
}

static int json_map_key(void *ctx, const unsigned char *ukey, size_t len)
{
  struct json_ctx_t *parser = ctx;


  const char *key = strndup(ukey, len);
  strncpy(parser->state, ukey, len);
  parser->state[len] = 0;

  /*syslog(LOG_DEBUG, "json_map_key %s=%s", key, parser->state);*/

  return 1;
}


/* yajl_callback functions.
 * They handle the "events" of yajl.
 */
yajl_callbacks yajl_cbs[] = {
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,    
  json_string,
  NULL,
  json_map_key,
  NULL,
  NULL,
    NULL
};

size_t parse_json(void *ptr, size_t size,  size_t  nmemb,  void  *stream) {
  size_t total_size = size * nmemb;
  yajl_handle y_handle = (yajl_handle)stream;
  syslog(LOG_DEBUG, "about to parse");

  yajl_parse(y_handle, ptr, total_size);
    
  return total_size;
}

/*****************************  Common Section  *****************************/

static const char plugin_id[] = "$Id: browserid.c,v 1.180 2011/08/11 17:00:00 mel Exp $";

static char *quote (char *str);

struct context;

static const unsigned short version = 5;

static void browserid_common_mech_dispose(void *conn_context,
					  const sasl_utils_t *utils)
{
    syslog(LOG_EMERG, "browserid_server_mech_dispose");

    return;
}

/**
 * Application is shutting down. Your FREE, FREE!
 */
static void browserid_common_mech_free(void *glob_context,
				       const sasl_utils_t *utils)
{
    syslog(LOG_EMERG, "browserid_common_mech_free");
    return;
}

/*****************************  Server Section  *****************************/



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
    syslog(LOG_EMERG, "browserid_server_mech_new");

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

    CURL *handle;
    CURLcode code;
    const char*bid_url_fmt;
    char bid_url[8192];
    yajl_handle y_handle;
    struct json_ctx_t *json_ctx;


    syslog(LOG_EMERG, "browserid_server_mech_step clientinlen=%d", clientinlen);


    /* should have received assertion NUL audience */

    /* get assertion */
    assertion = clientin;
    syslog(LOG_EMERG, "Assertion: [%s]", assertion);

    while ((lup < clientinlen) && (clientin[lup] != 0)) ++lup;

    if (lup >= clientinlen) {
	SETERROR(sparams->utils, "Can only find browserid assertion (no audience)");
	return SASL_BADPROT;
    }

    /* get audience */
    ++lup;
    audience = clientin + lup;
    while ((lup < clientinlen) && (clientin[lup] != 0)) ++lup;

    audience_len = (unsigned) (clientin + lup - audience);

    syslog(LOG_EMERG, "lup = %d clientinlen = %d", lup, clientinlen);

    if (lup != clientinlen) {
	SETERROR(sparams->utils,
		 "Oh snap, more data than we were expecting in the BROWSER-ID plugin\n");
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

    syslog(LOG_EMERG, "Server side, we've got ASSERTION[%s] AUDIENCE[%s]", assertion, audience_copy);


    /* BEGIN BrowserID */

    bid_url_fmt = "https://browserid.org/verify?assertion=%s&audience=%s";
    /*"http://localhost:8001/en-US/media/js/browserid.json";*/
    
    sprintf(bid_url, bid_url_fmt, assertion, audience_copy);
    syslog(LOG_ERR, "bidurl = %s", bid_url);

    json_ctx = malloc(sizeof(struct json_ctx_t));
    
    y_handle = yajl_alloc(yajl_cbs, NULL, /* NULL);*/
			  json_ctx);
    if (!y_handle) {
      syslog(LOG_ERR, "Could not alloc YAJL");
    }

    if (0 != curl_global_init(CURL_GLOBAL_SSL)) {
      syslog(LOG_ERR, "curl_global_init was non-zero");
      return -1;
    }

    handle = curl_easy_init();
    if (handle == NULL) {
      syslog(LOG_ERR, "Unable to curl_easy_init");
    }

    if (0 != curl_easy_setopt(handle, CURLOPT_URL, bid_url))
      syslog(LOG_DEBUG, "curl setopt url failed");

    if (0 != curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1))
      syslog(LOG_DEBUG, "curl setopt follow");

    if (0 != curl_easy_setopt(handle, CURLOPT_USE_SSL, CURLUSESSL_TRY))
      syslog(LOG_DEBUG, "curl setopt ssl failed");

    if (0 != curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, parse_json))
      syslog(LOG_DEBUG, "curl setopt write fn failed");

    if (0 != curl_easy_setopt(handle, CURLOPT_WRITEDATA, y_handle))
      syslog(LOG_DEBUG, "curl setopt writedata failed");


    code = curl_easy_perform(handle);
    
    syslog(LOG_DEBUG, "curl perform finished");
    if (code != 0)
      syslog(LOG_DEBUG, "curl perform failed");

    yajl_complete_parse(y_handle);
    yajl_free(y_handle);

    curl_easy_cleanup(handle);

    if (strcasecmp(json_ctx->status, "okay") == 0) {
      syslog(LOG_DEBUG, "Yes, we're all good! %s %s %s",
	     json_ctx->email, 
	     json_ctx->audience,
	     json_ctx->issuer);
        result = sparams->canon_user(sparams->utils->conn,
				     json_ctx->email, 0,
				     SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams);
	if (result != SASL_OK) {
	  _plug_free_string(sparams->utils, &audience_copy);
	  return result;
	}
    } else {
        syslog(LOG_ERR, "No dice, STATUS=[%s] REASON=[%s]", json_ctx->status, json_ctx->reason);
      /* TODO sprintf error message with bid_resp->reason  */
      SETERROR(sparams->utils,
	       "Browserid.org assertion verification failed.");
      return SASL_BADPROT;
    }
    
    free(json_ctx);
    /* END BrowserID */

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
    syslog(LOG_EMERG, "browserid_server_mech_dispose");
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
	NULL,            		/* glob_context */
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
    openlog("browserid-server", LOG_NDELAY, LOG_AUTH);
    syslog(LOG_EMERG, "browserid_server_plug_init");
    if (maxversion < SASL_SERVER_PLUG_VERSION) {
	SETERROR( utils, "ANONYMOUS version mismatch" );
	return SASL_BADVERS;
    }
    
    *out_version = SASL_SERVER_PLUG_VERSION;
    *pluglist = browserid_server_plugins;
    *plugcount = 1;  
    return SASL_OK;
}

/*****************************  Client Section  *****************************/

typedef struct client_context {
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
    syslog(LOG_EMERG, "browserid_client_mech_new");
    client_context_t *context;

    context = params->utils->malloc(sizeof(client_context_t));
    if (context == NULL) {
	MEMERROR( params->utils );
	return SASL_NOMEM;
    }
    
    memset(context, 0, sizeof(client_context_t));
    
    *conn_context = context;
    return SASL_OK;
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
    const char *user = NULL, *authid = "ozten", *browser_assertion = NULL, *browser_audience = NULL;
    int browser_assertion_result = SASL_OK;
    int browser_audience_result = SASL_OK;
    int result;
    char *p;

    syslog(LOG_EMERG, "browserid_client_mech_new");

    if (!params
	|| !clientout
	|| !clientoutlen
	|| !oparams) {
      PARAMERROR( params->utils );
	return SASL_BADPARAM;
    }

    /* try to get the assertion */    
    if (oparams->authid == NULL) {
      /* TODO get_authid should be get_assertion */
	browser_assertion_result = _plug_get_userid(params->utils, &browser_assertion, prompt_need);
	
	if ((browser_assertion_result != SASL_OK) && (browser_assertion_result != SASL_INTERACT))
	    return browser_assertion_result;
    }

    /* try to get the audience */
    if (oparams->user == NULL) {
      /* TODO get_authid should be get_audience */
	browser_audience_result = _plug_get_authid(params->utils, &browser_audience, prompt_need);
	
	if ((browser_audience_result != SASL_OK) && (browser_audience_result != SASL_INTERACT))
	    return browser_audience_result;
    }

    /* free prompts we got */
    if (prompt_need && *prompt_need) {
	params->utils->free(*prompt_need);
	*prompt_need = NULL;
    }

    /* if there are prompts not filled in */
    if ((browser_audience_result == SASL_INTERACT) || (browser_assertion_result == SASL_INTERACT)) {
	/* make the prompt list */
	result =
	    _plug_make_prompts(params->utils, prompt_need,
			       browser_assertion_result == SASL_INTERACT ?
			       "Please enter your assertion" : NULL,
			       NULL,
			       browser_audience_result == SASL_INTERACT ?
			       "Please enter your website (example.com)" : NULL,
			       NULL,
			       NULL, NULL,
			       NULL, NULL, NULL,
			       NULL, NULL, NULL);
	if (result != SASL_OK) goto cleanup;
	return SASL_INTERACT;
    }
    
    syslog(LOG_EMERG, "YO ASSERTION=[%s] AUDIENCE=[%s]", browser_assertion, browser_audience);
    
    /* TODO ... I think this is SASL Abuse. This should come as a second step. */
    params->canon_user(params->utils->conn, browser_assertion, 0,
			SASL_CU_AUTHZID, oparams);
    params->canon_user(params->utils->conn, browser_audience, 0,
			SASL_CU_AUTHID, oparams);

    if (result != SASL_OK) goto cleanup;

    syslog(LOG_EMERG, "Got passed canon_user");

    /* send assertion NUL audience NUL */
    /* we should not use oparams... use context instead ? */
    *clientoutlen = (strlen(browser_assertion) + 1 + strlen(browser_audience));

    syslog(LOG_EMERG, " hmm clientoutlen is going to be %d", clientoutlen);

    result = _plug_buf_alloc(params->utils, &(context->out_buf),
			     &(context->out_buf_len), *clientoutlen +1);
    if (result != SASL_OK) goto cleanup;

    memset(context->out_buf, 0, *clientoutlen + 1);
    p = context->out_buf;
    if (browser_assertion && *browser_assertion) {
        memcpy(p, oparams->user, oparams->ulen);
	p += oparams->ulen;
    }
    memcpy(++p, oparams->authid, oparams->alen);
    p += oparams->alen;

    *clientout = context->out_buf;


    /* server step here? */

    /* set oparams */
    oparams->doneflag = 1;
    oparams->mech_ssf = 0;
    oparams->maxoutbuf = 0;
    oparams->encode_context = NULL;
    oparams->encode = NULL;
    oparams->decode_context = NULL;
    oparams->decode = NULL;
    oparams->param_version = 0;


    /* write to clientout */

  cleanup:

    /*return result;*/
    return SASL_OK;
}

/**
 * Client side connection is no longer in use.
 */
static void browserid_client_mech_dispose(void *conn_context,
					  const sasl_utils_t *utils)
{
    syslog(LOG_EMERG, "browserid_client_mech_dispose");

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
	| SASL_FEAT_ALLOWS_PROXY, 	/* features */
	NULL,				/* required_prompts */
	NULL,		                /* glob_context */
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
    openlog("browserid-client", LOG_NDELAY, LOG_AUTH);
    syslog(LOG_EMERG, "browserid_client_plug_init_plugin initialized");
    if (maxversion < SASL_CLIENT_PLUG_VERSION) {
	SETERROR( utils, "ANONYMOUS version mismatch" );
	return SASL_BADVERS;
    }
    
    *out_version = SASL_CLIENT_PLUG_VERSION;
    *pluglist = browserid_client_plugins;
    *plugcount = 1;
    return SASL_OK;
}
