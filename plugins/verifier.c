#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <curl/curl.h>
#include <sasl/sasl.h> /* saslplug.h should have included this ?!? */
#include <sasl/saslplug.h>
#include "yajl/yajl_parse.h"
#include "yajl/yajl_tree.h"

#include <verifier.h>

static int json_number(void *ctx, const char* val, size_t len);

static int json_string(void *ctx, const unsigned char *ukey, size_t len);

static int json_map_key(void *ctx, const unsigned char *ukey, size_t len);

static size_t parse_json(void *ptr, size_t size, size_t nmemb, void *stream);

/* yajl_callback functions */
yajl_callbacks yajl_cbs[] = {
	NULL,	      /* NULL */
	NULL,	      /* boolean */
	NULL,	      /* integer */
	NULL,	      /* double */
	json_number,
	json_string,
	NULL,	      /* start map */
	json_map_key,
	NULL,	      /* end map */
	NULL,	      /* start array */
	NULL	      /* end array */
};

static int json_number(void *ctx, const char* ukey, size_t len)
{
	struct browserid_response_t *parser = ctx;
	char *val = strndup(ukey, len);
	if (strcasecmp(parser->state, "valid-until") == 0) {
		sscanf(val, "%lli", &parser->valid_until);
		syslog(LOG_DEBUG, "valid-until=%llu", parser->valid_until);
	} else {
		syslog(LOG_DEBUG, "Unknown state %s", parser->state);
	}
	return 1;
}

static int json_string(void *ctx, const unsigned char *ukey, size_t len)
{
	struct browserid_response_t *parser = ctx;
	const char *key = parser->state;
	const char *val = strndup(ukey, len);
	syslog(LOG_DEBUG, "json_string %s=%s %u", key, val, len);
	syslog(LOG_DEBUG, "size was %zu", len);

	if (strcasecmp(key, "status") == 0) {
		strcpy(parser->status, val);
		parser->status[len] = '\0';
		syslog(LOG_DEBUG, "status=%s from %s", parser->status, val);
	} else if (strcasecmp(key, "email") == 0) {
		strcpy(parser->email, val);
		parser->email[len] = '\0';
		syslog(LOG_DEBUG, "email=%s", parser->email);
	} else if (strcasecmp(key, "audience") == 0) {
		strcpy(parser->audience, val);
		parser->audience[len] = '\0';
		syslog(LOG_DEBUG, "audience = %s", parser->audience);
	} else if (strcasecmp(key, "issuer") == 0) {
		strcpy(parser->issuer, val);
		parser->issuer[len] = '\0';
		syslog(LOG_DEBUG, "issuer=%s", parser->issuer);
	} else if (strcasecmp(key, "valid-until") == 0) {
		sscanf(val, "%lli", &parser->valid_until);
		syslog(LOG_DEBUG, "valid-until=%llu", parser->valid_until);
	} else if (strcasecmp(key, "reason") == 0) {
		strcpy(parser->reason, val);
		parser->reason[len] = '\0';
		syslog(LOG_DEBUG, "reason=%s", parser->reason);
	} else {
		syslog(LOG_DEBUG, "unknown json_string %s=%s", key, val);
	}
	return 1;
}

static int json_map_key(void *ctx, const unsigned char *ukey, size_t len)
{
	struct browserid_response_t *parser = ctx;
	const char *key = strndup(ukey, len);
	strcpy(parser->state, key);
	parser->state[len] = '\0';
	syslog(LOG_DEBUG, "Preparing %s from %s", parser->state, key);
	return 1;
}

static size_t parse_json(void *ptr, size_t size, size_t	 nmemb, void *stream)
{
	size_t total_size = size * nmemb;
	yajl_handle y_handle = (yajl_handle)stream;
	yajl_parse(y_handle, ptr, total_size);
	return total_size;
}

/**
 * Attempts to verify an assertion and audience against the
 * BrowserID service. This call goes over the network.
 *
 * Service is configurable via 'browserid_endpoint'.
 */
int browserid_verify(const sasl_utils_t *utils,
		     struct browserid_response_t *browserid_response,
		     const char *assertion,
		     const char *audience)
{
	CURL *handle;
	CURLcode code;
	const char *bid_url;
	char *bid_body;
	char *bid_body_fmt = "assertion=%s&audience=%s";

	yajl_handle y_handle;
	int r;

	r = utils->getopt(utils->getopt_context, "BROWSER-ID",
			  "browserid_endpoint", &bid_url, NULL);
	if (r || !bid_url) {
		bid_url = 
		    "https://browserid.org/verify";
	}

	syslog(LOG_INFO, "bidurl = %s", bid_url);

	bid_body = malloc(strlen(bid_body_fmt) + 
			  strlen(assertion) + strlen(audience));
	sprintf(bid_body, bid_body_fmt, assertion, audience);
	syslog(LOG_INFO, "bid_body = %s", bid_body);

	strcpy(browserid_response->state, "");
	strcpy(browserid_response->status, "");
	strcpy(browserid_response->email, "");
	strcpy(browserid_response->audience, "");
	strcpy(browserid_response->issuer, "");
	browserid_response->valid_until = 0;
	strcpy(browserid_response->reason, "");

	y_handle = yajl_alloc(yajl_cbs, NULL, browserid_response);
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
		syslog(LOG_ERR, "curl setopt url failed");
	if (0 != curl_easy_setopt(handle, CURLOPT_POST, 1))
		syslog(LOG_ERR, "curl setopt post failed");
	if (0 != curl_easy_setopt(handle, CURLOPT_POSTFIELDS, bid_body))
		syslog(LOG_ERR, "curl setopt postfields failed");
	if (0 != curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1))
		syslog(LOG_DEBUG, "curl setopt follow");

	if (0 != curl_easy_setopt(handle, CURLOPT_USE_SSL, CURLUSESSL_TRY))
		syslog(LOG_DEBUG, "curl setopt ssl failed");

	if (0 != curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, parse_json))
		syslog(LOG_ERR, "curl setopt write fn failed");

	if (0 != curl_easy_setopt(handle, CURLOPT_WRITEDATA, y_handle))
		syslog(LOG_ERR, "curl setopt writedata failed");

	code = curl_easy_perform(handle);

	if (code == 0) {
		syslog(LOG_DEBUG, "curl_easy_perform finished");
	} else {
		syslog(LOG_EMERG, "curl_easy_perform failed [%u] %s", code, 
		       curl_easy_strerror(code));
		strcpy(browserid_response->status, "curl-error");
		strcpy(browserid_response->reason, curl_easy_strerror(code));
	}

	yajl_complete_parse(y_handle);
	yajl_free(y_handle);
	
	curl_easy_cleanup(handle);
	free(bid_body);
	return 1;
}
