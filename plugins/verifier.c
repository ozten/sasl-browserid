#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <curl/curl.h>
#include <sasl/sasl.h> /* saslplug.h should have included this ?!? */
#include <sasl/saslplug.h>
#include "plugin_common.h"

#include "yajl/yajl_tree.h"



#include <verifier.h>

#define JSON_BUFFER 256

/* Helper struct for CURL response */
struct json_response {
  char *memory;
  size_t size;
  size_t realsize;
  int memerr;
};

/** Callback function for streaming CURL response */
static size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	size_t nextsize;
	struct json_response *mem = (struct json_response *)userp;

	if (mem->size + realsize >= mem->realsize) {
		nextsize = mem->size + realsize + JSON_BUFFER;
		if (nextsize < mem->realsize) {
			syslog(LOG_ERR, "Buffer Overflow, ignoring new contents");
			return realsize;
		}
		mem->realsize = nextsize;
		void *tmp = malloc(mem->size + realsize + JSON_BUFFER);
		if (tmp == NULL) {
			syslog(LOG_ERR, "Unable to grow json_response tmp buffer");
			mem->memerr = 1;
			return realsize;
		}
		memcpy(tmp, mem->memory, mem->size);
		free(mem->memory);
		mem->memory = malloc(mem->size + realsize + JSON_BUFFER);
		if (mem->memory == NULL) {
			syslog(LOG_ERR, "Unable to grow json_response memory slot");
			mem->memerr = 1;
			return realsize;
		}
		memcpy(mem->memory, tmp, mem->size);
		free(tmp);
	}

	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;
	return realsize;
}

static int parse(const char* resp,
		  struct browserid_response_t *browserid_response);

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
	struct json_response json_text;
	char *resp;


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
	if (bid_body == NULL) {
		MEMERROR( utils );
		return SASL_NOMEM;
	}
	sprintf(bid_body, bid_body_fmt, assertion, audience);
	syslog(LOG_INFO, "bid_body = %d %s", strlen(bid_body), bid_body);

	strcpy(browserid_response->state, "");
	strcpy(browserid_response->status, "");
	strcpy(browserid_response->email, "");
	strcpy(browserid_response->audience, "");
	strcpy(browserid_response->issuer, "");
	browserid_response->expires = 0;
	strcpy(browserid_response->reason, "");

	if (0 != curl_global_init(CURL_GLOBAL_SSL)) {
		syslog(LOG_ERR, "curl_global_init was non-zero");
		return SASL_FAIL;
	}

	handle = curl_easy_init();
	if (handle == NULL) {
		syslog(LOG_ERR, "Unable to curl_easy_init");
		return SASL_FAIL;
	}
	if (0 != curl_easy_setopt(handle, CURLOPT_URL, bid_url))
		syslog(LOG_ERR, "curl setopt url failed");
	if (0 != curl_easy_setopt(handle, CURLOPT_POST, 1))
		syslog(LOG_ERR, "curl setopt post failed");
	if (0 != curl_easy_setopt(handle, CURLOPT_POSTFIELDS, bid_body))
		syslog(LOG_ERR, "curl setopt postfields failed");
	if (0 != curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1))
		syslog(LOG_DEBUG, "curl setopt follow");
	if (0 != curl_easy_setopt(handle, CURLOPT_USE_SSL, CURLUSESSL_ALL))
		syslog(LOG_DEBUG, "curl setopt ssl failed");
	if (0 != curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION,
				  write_cb))
		syslog(LOG_ERR, "curl setopt write fn failed");

	json_text.size = 0;
	json_text.memerr = 0;
	json_text.realsize = JSON_BUFFER;
	json_text.memory = malloc(JSON_BUFFER);
	if (json_text.memory == NULL) {
		MEMERROR( utils );
		return SASL_NOMEM;
	}

	if (0 != curl_easy_setopt(handle, CURLOPT_WRITEDATA, &json_text))
		syslog(LOG_ERR, "curl setopt writedata failed");

	code = curl_easy_perform(handle);

	if (json_text.memerr == 1) {
		MEMERROR( utils );
		return SASL_NOMEM;
	}

	if (code == 0) {
		r = parse(json_text.memory, browserid_response);
	} else {
		syslog(LOG_EMERG, "curl_easy_perform failed [%u] %s", code,
		       curl_easy_strerror(code));
		strcpy(browserid_response->status, "curl-error");
		strcpy(browserid_response->reason, curl_easy_strerror(code));
	}

	curl_easy_cleanup(handle);
	free(bid_body);
	return r;
}

static int parse(const char* resp,
		  struct browserid_response_t *browserid_response)
{
	yajl_val tree = NULL;
	char err_buf[256];

	syslog(LOG_DEBUG, "beginning parse");

	tree = yajl_tree_parse(resp, err_buf, 255);

	if (!tree) {
		syslog(LOG_ERR, "bid resp=%s", resp);
		syslog(LOG_ERR, "Error parsing BrowserID response [%s]",
		       err_buf);
		return SASL_FAIL;
	}

	syslog(LOG_DEBUG, "Obtained parser tree");

	const char *status_path[] = { "status", (const char *) 0 };
	yajl_val status = yajl_tree_get(tree, status_path, yajl_t_string);
	if (!status) {
		syslog(LOG_ERR, "bid resp=%s", resp);
		syslog(LOG_EMERG, "Expected field status is missing");
		return SASL_FAIL;
	}
	syslog(LOG_DEBUG, "Obtained status %s", status);

	strcpy(browserid_response->status, status->u.string);

	if (strcasecmp(status->u.string, "okay") == 0) {
		const char *email_path[] = { "email", (const char *) 0 };
		const char *audience_path[] = { "audience", (const char *) 0 };
		const char *issuer_path[] = { "issuer", (const char *) 0 };
		const char *expires_path[] = { "expires", (const char *) 0 };

		yajl_val email, audience, issuer, expires;

		email = yajl_tree_get(tree, email_path, yajl_t_string);
		if (!email) {
			syslog(LOG_ERR, "Expected field email is missing");
		} else {
			strcpy(browserid_response->email, email->u.string);
		}

		audience = yajl_tree_get(tree, audience_path, yajl_t_string);
		if (!audience) {
			syslog(LOG_ERR, "Expected field audience is missing");
		} else {
			strcpy(browserid_response->audience, audience->u.string);
		}

		issuer = yajl_tree_get(tree, issuer_path, yajl_t_string);
		if (!issuer) {
			syslog(LOG_ERR, "Expected field issuer is missing");
		} else {
			strcpy(browserid_response->issuer, issuer->u.string);
		}

		expires = yajl_tree_get(tree, expires_path, yajl_t_number);
		if (!expires) {
			syslog(LOG_INFO, "Expected field expires is missing or not a number");
		} else {
			browserid_response->expires = expires->u.number.i;
		}
	} else {
		const char *reason_path[] = { "reason", (const char *) 0 };
		yajl_val reason = yajl_tree_get(tree, reason_path, yajl_t_string);
		if (!reason) {
			syslog(LOG_ERR, "Expected field reason is missing");
		} else {
			strcpy(browserid_response->reason, reason->u.string);
		}
		return SASL_FAIL;
	}
	return SASL_OK;
}
