#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <unistd.h>

#include <curl/curl.h>

#include "yajl/yajl_parse.h"
#include "yajl/yajl_tree.h"

/* I think this can be anything */
struct json_ctx_t {
    char state[64];
    char status[64]; /* "okay" */
    char email[1024]; /* shout@ozten.com */
    char audience[1024]; /* mozillians.org */
    /* long valid_until; timeout */
    char issuer[1024]; /* browserid.org:443 */
    char reason[1024]; /* Set if status is failure */
};

/* yajl callback functions */
static int json_string(void *ctx, const unsigned char *ukey, size_t len)
{
    struct json_ctx_t *parser = ctx;
    const char *key = parser->state;
    const char *val = strndup(ukey, len);
    syslog(LOG_DEBUG, "json_string %s=%s", key, val);

    if (strcasecmp(key, "status") == 0) {
        strncpy(parser->status, ukey, len);
        syslog(LOG_DEBUG, "status=%s", val);
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

int 
main (int argc, char **argv) {

    CURL *handle;
    CURLcode code;
    const char*bid_url_fmt;
    char bid_url[8192];

    if (argc < 3) {
        syslog(LOG_ERR, "Not enough arguments, expected assertion then audience");
        return 1;
    } else {
        syslog(LOG_DEBUG, "inputs %s %s", argv[1], argv[2]);
    }

    DANGER... THIS CODE IS OUT OF DATE... verify only accepts POST NOW
    bid_url_fmt = "https://browserid.org/verify?assertion=%s&audience=%s";
     /*"http://localhost:8001/en-US/media/js/browserid.json";*/
    
    sprintf(bid_url, bid_url_fmt, argv[1], argv[2]);
    syslog(LOG_ERR, "bidurl = %s", bid_url);

    yajl_handle y_handle;
    struct json_ctx_t *json_ctx;

    openlog("test", LOG_NDELAY, LOG_USER);

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
    } else {
        syslog(LOG_ERR, "No dice, REASON=[%s]", json_ctx->reason);
    }
    
    free(json_ctx);
    closelog();
    return 0;
}
