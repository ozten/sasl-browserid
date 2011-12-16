#include <config.h>

#include <stdlib.h>
#include <string.h>

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
  sasl_utils_t *utils;
};

/** Callback function for streaming CURL response */
static size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	size_t nextsize;
	struct json_response *mem = (struct json_response *)userp;

	/** check for multiplication overflow */
	if (size != 0 && nmemb != 0 && realsize < size) {
	    /** CURL spec says number of bytes handled should be returned
	     * http://curl.haxx.se/libcurl/c/curl_easy_setopt.html
	     */
		mem->utils->log(NULL, SASL_LOG_ERR, "Integer Overflow early, ignoring new contents");
		return 0;
	}
	if (mem->size + realsize >= mem->realsize) {
		nextsize = mem->size + realsize + JSON_BUFFER;
		if (nextsize < mem->realsize) {
			mem->utils->log(NULL, SASL_LOG_ERR, "Integer Overflow, ignoring new contents");
			return 0;
		}
		mem->realsize = nextsize;
		void *tmp = malloc(mem->size + realsize + JSON_BUFFER);
		if (tmp == NULL) {
			mem->utils->log(NULL, SASL_LOG_ERR, "Unable to grow json_response tmp buffer");
			mem->memerr = 1;
			return 0;
		}
		memcpy(tmp, mem->memory, mem->size);
		free(mem->memory);
		mem->memory = malloc(mem->size + realsize + JSON_BUFFER);
		if (mem->memory == NULL) {
			mem->utils->log(NULL, SASL_LOG_ERR, "Unable to grow json_response memory slot");
			mem->memerr = 1;
			return 0;
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
		 struct browserid_response_t *browserid_response,
		 const sasl_utils_t *utils);

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
	struct json_response json_text; /* context */
	char *resp;


	int r;

	r = utils->getopt(utils->getopt_context, "BROWSER-ID",
			  "browserid_endpoint", &bid_url, NULL);
	if (r || !bid_url) {
		bid_url =
		    "https://browserid.org/verify";
	}

	utils->log(NULL, SASL_LOG_NOTE, "bidurl = %s", bid_url);

	bid_body = malloc(strlen(bid_body_fmt) +
			  strlen(assertion) + strlen(audience) + 1);
	if (bid_body == NULL) {
		MEMERROR( utils );
		return SASL_NOMEM;
	}
	sprintf(bid_body, bid_body_fmt, assertion, audience);
	utils->log(NULL, SASL_LOG_NOTE, "bid_body = %d %s", strlen(bid_body), bid_body);

	strcpy(browserid_response->status, "");
	strcpy(browserid_response->email, "");
	strcpy(browserid_response->audience, "");
	strcpy(browserid_response->issuer, "");
	browserid_response->expires = 0;
	strcpy(browserid_response->reason, "");

	if (0 != curl_global_init(CURL_GLOBAL_SSL)) {
		utils->log(NULL, SASL_LOG_ERR, "curl_global_init was non-zero");
		return SASL_FAIL;
	}

	handle = curl_easy_init();
	if (handle == NULL) {
		utils->log(NULL, SASL_LOG_ERR, "Unable to curl_easy_init");
		return SASL_FAIL;
	}
	if (0 != curl_easy_setopt(handle, CURLOPT_URL, bid_url)) {
		utils->log(NULL, SASL_LOG_ERR, "curl setopt url failed");
		return SASL_FAIL;
	}
	if (0 != curl_easy_setopt(handle, CURLOPT_POST, 1)) {
		utils->log(NULL, SASL_LOG_ERR, "curl setopt post failed");
		return SASL_FAIL;
	}
	if (0 != curl_easy_setopt(handle, CURLOPT_POSTFIELDS, bid_body)) {
		utils->log(NULL, SASL_LOG_ERR, "curl setopt postfields failed");
		return SASL_FAIL;
	}
	if (0 != curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1)) {
		utils->log(NULL, SASL_LOG_DEBUG, "curl setopt follow");
		return SASL_FAIL;
	}
	if (0 != curl_easy_setopt(handle, CURLOPT_USE_SSL, CURLUSESSL_ALL)) {
		utils->log(NULL, SASL_LOG_DEBUG, "curl setopt ssl failed");
		return SASL_FAIL;
	}
	if (0 != curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION,
				  write_cb)) {
		utils->log(NULL, SASL_LOG_ERR, "curl setopt write fn failed");
		return SASL_FAIL;
	}

	json_text.size = 0;
	json_text.memerr = 0;
	json_text.realsize = JSON_BUFFER;
	json_text.utils = utils;
	json_text.memory = malloc(JSON_BUFFER);
	if (json_text.memory == NULL) {
		MEMERROR( utils );
		return SASL_NOMEM;
	}

	if (0 != curl_easy_setopt(handle, CURLOPT_WRITEDATA, &json_text)) {
		utils->log(NULL, SASL_LOG_ERR, "curl setopt writedata failed");
		return SASL_FAIL;
	}

	code = curl_easy_perform(handle);

	if (json_text.memerr == 1) {
		MEMERROR( utils );
		return SASL_NOMEM;
	}

	if (code == 0) {
		r = parse(json_text.memory, browserid_response, utils);
	} else {
		utils->log(NULL, SASL_LOG_ERR, "curl_easy_perform failed [%u] %s", code,
		       curl_easy_strerror(code));
		strcpy(browserid_response->status, "curl-error");
		if (strlen(curl_easy_strerror(code)) < MAX_RESP_FIELD) {
			strcpy(browserid_response->reason, curl_easy_strerror(code));
		} else {
			utils->log(NULL, SASL_LOG_ERR, curl_easy_strerror(code));
			strcpy(browserid_response->reason, "Curl failed, error message too large see syslog.");
		}
	}

	curl_easy_cleanup(handle);
	free(bid_body);
	return r;
}

static int parse(const char* resp,
		 struct browserid_response_t *browserid_response,
		 const sasl_utils_t *utils)
{
	yajl_val tree = NULL;
	char err_buf[256];

	utils->log(NULL, SASL_LOG_DEBUG, "beginning parse %s", resp);

	tree = yajl_tree_parse(resp, err_buf, 255);

	if (!tree) {
		utils->log(NULL, SASL_LOG_ERR, "bid resp=%s", resp);
		utils->log(NULL, SASL_LOG_ERR, "Error parsing BrowserID response [%s]",
		       err_buf);
		return SASL_FAIL;
	}

	utils->log(NULL, SASL_LOG_DEBUG, "Obtained parser tree");

	const char *status_path[] = { "status", (const char *) 0 };
	yajl_val status = yajl_tree_get(tree, status_path, yajl_t_string);
	if (!status || strlen(status->u.string) >= MAX_STATUS) {
		utils->log(NULL, SASL_LOG_ERR, "bid resp=%s", resp);
		utils->log(NULL, SASL_LOG_ERR, "Expected field status is missing or too large");
		return SASL_FAIL;
	}
	utils->log(NULL, SASL_LOG_DEBUG, "Obtained status %s", status->u.string);

	strcpy(browserid_response->status, status->u.string);

	if (strcasecmp(status->u.string, "okay") == 0) {
		const char *email_path[] = { "email", (const char *) 0 };
		const char *audience_path[] = { "audience", (const char *) 0 };
		const char *issuer_path[] = { "issuer", (const char *) 0 };
		const char *expires_path[] = { "expires", (const char *) 0 };

		yajl_val email, audience, issuer, expires;

		email = yajl_tree_get(tree, email_path, yajl_t_string);
		if (!email || strlen(email->u.string) >= MAX_RESP_FIELD) {
			/* Can't continue without email */
			utils->log(NULL, SASL_LOG_ERR, "bid resp=%s", resp);
			utils->log(NULL, SASL_LOG_ERR, "Expected field email is missing or too large.");
			return SASL_FAIL;
		} else {
			strcpy(browserid_response->email, email->u.string);
		}

		audience = yajl_tree_get(tree, audience_path, yajl_t_string);
		if (!audience) {
			utils->log(NULL, SASL_LOG_ERR, "Expected field audience is missing");
		} else {
			if (strlen(audience->u.string) < MAX_RESP_FIELD) {
				strcpy(browserid_response->audience, audience->u.string);
			} else {
				utils->log(NULL, SASL_LOG_WARN, "Audience is too large, skipping");
			}
		}

		issuer = yajl_tree_get(tree, issuer_path, yajl_t_string);
		if (!issuer) {
			utils->log(NULL, SASL_LOG_ERR, "Expected field issuer is missing");
		} else {
			if (strlen(issuer->u.string) < MAX_RESP_FIELD) {
				strcpy(browserid_response->issuer, issuer->u.string);
			} else {
				utils->log(NULL, SASL_LOG_WARN, "Issuer is too large, skipping");
			}			
		}

		expires = yajl_tree_get(tree, expires_path, yajl_t_number);
		if (!expires) {
			utils->log(NULL, SASL_LOG_NOTE, "Expected field expires is missing or not a number");
		} else {
			browserid_response->expires = expires->u.number.i;
		}
	} else {
		const char *reason_path[] = { "reason", (const char *) 0 };
		yajl_val reason = yajl_tree_get(tree, reason_path, yajl_t_string);
		if (!reason) {
			utils->log(NULL, SASL_LOG_ERR, "Expected field reason is missing");
		} else {
			if (strlen(reason->u.string) < MAX_RESP_FIELD) {
				strcpy(browserid_response->reason, reason->u.string);
			} else {
				utils->log(NULL, SASL_LOG_WARN, "BrowserID verifier failure reason is too large to copy, skipping.");
			}
			
		}
		return SASL_FAIL;
	}
	return SASL_OK;
}
