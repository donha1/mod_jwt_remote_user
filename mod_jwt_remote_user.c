#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_strings.h"
#include <string.h>
#include <stdlib.h>
module AP_MODULE_DECLARE_DATA bearer_remote_user_module;
typedef struct {
    const char *jwt_remote_user_claim;
} jwt_remote_user_claim_config;
/* Base64 URL decoding table */
static unsigned char b64url_table[256];

static void *create_jwt_remote_user_claim_config(apr_pool_t *p, server_rec *s) {
    jwt_remote_user_claim_config *conf = apr_pcalloc(p, sizeof(*conf));
    conf->jwt_remote_user_claim = "preferred_username"; // Default value
    return conf;
}

static const char *set_jwt_remote_user_claim(cmd_parms *cmd, void *cfg, const char *arg) {
    jwt_remote_user_claim_config *conf = (jwt_remote_user_claim_config *) ap_get_module_config(cmd->server->module_config, &bearer_remote_user_module);
    conf->jwt_remote_user_claim = arg;
    return NULL;
}

static const command_rec jwt_remote_user_claim_cmds[] = {
    AP_INIT_TAKE1("JWTRemoteUserClaim", set_jwt_remote_user_claim, NULL, RSRC_CONF, "The JWT remote user claim value"),
    {NULL}
};

static void init_b64url_table() {
    memset(b64url_table, 0x80, 256);
    for (int i = 'A'; i <= 'Z'; i++) b64url_table[i] = i - 'A';
    for (int i = 'a'; i <= 'z'; i++) b64url_table[i] = i - 'a' + 26;
    for (int i = '0'; i <= '9'; i++) b64url_table[i] = i - '0' + 52;
    b64url_table['-'] = 62;
    b64url_table['_'] = 63;
}

static unsigned char *base64url_decode(apr_pool_t *p, const char *data, int *out_len) {
    int len = strlen(data);
    char *b64 = apr_pstrdup(p, data);

    // Replace URL-safe chars and pad
    for (int i = 0; i < len; i++) {
        if (b64[i] == '-') b64[i] = '+';
        else if (b64[i] == '_') b64[i] = '/';
    }
    int pad = len % 4;
    if (pad > 0) {
        b64 = apr_pstrcat(p, b64, pad == 2 ? "==" : "=", NULL);
        len = strlen(b64);
    }

    unsigned char *out = apr_palloc(p, len * 3 / 4 + 1);
    unsigned char *pos = out;

    unsigned int val = 0;
    int valb = -8;

    for (int i = 0; i < len; i++) {
        unsigned char c = b64[i];
        if (c == '=') break;
        unsigned char d = b64url_table[c];
        if (d & 0x80) continue; // skip invalid
        val = (val << 6) | d;
        valb += 6;
        if (valb >= 0) {
            *pos++ = (unsigned char)(val >> valb);
            valb -= 8;
        }
    }
    *out_len = pos - out;
    return out;
}

static const char *extract_preferred_username(apr_pool_t *p, const char *json, int len, const char *key) {	
	
    const char *pos = strstr(json, key);
    if (!pos) return NULL;

    pos += strlen(key);
    while (*pos && (*pos == ' ' || *pos == '\t' || *pos == ':')) pos++;
    if (*pos != '"') return NULL;
    pos++;
    const char *start = pos;
    while (*pos && *pos != '"') pos++;
    if (*pos != '"') return NULL;

    return apr_pstrndup(p, start, pos - start);
}

static int bearer_remote_user_handler(request_rec *r) {
    if (!r->headers_in) {
        return DECLINED;
    }

    const char *auth = apr_table_get(r->headers_in, "Authorization");
    if (!auth || strncasecmp(auth, "Bearer ", 7) != 0) {
        return DECLINED;
    }

    const char *token = auth + 7;
    char *token_copy = apr_pstrdup(r->pool, token);
	jwt_remote_user_claim_config *conf = (jwt_remote_user_claim_config *) ap_get_module_config(r->server->module_config, &bearer_remote_user_module);
 
	//ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Value of JWTRemoteUserClaim  = %s", conf->jwt_remote_user_claim);
    // Split JWT
    char *dot1 = strchr(token_copy, '.');
    if (!dot1) return DECLINED;
    *dot1 = '\0';
    char *dot2 = strchr(dot1 + 1, '.');
    if (!dot2) return DECLINED;
    *dot2 = '\0';

    const char *payload_b64 = dot1 + 1;

    int payload_len = 0;
    unsigned char *payload_json = base64url_decode(r->pool, payload_b64, &payload_len);
    if (!payload_json || payload_len == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to decode JWT payload");
        return HTTP_UNAUTHORIZED;
    }
    const char *key = (const char *)malloc(sizeof(conf->jwt_remote_user_claim) + 2);
	sprintf(key,"\"%s\"", conf->jwt_remote_user_claim);
	//ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Extract value of key  = %s", key);
    const char *username = extract_preferred_username(r->pool, (const char *)payload_json, payload_len, key);
	free(key);
    if (!username) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "%s not found in JWT",conf->jwt_remote_user_claim);
    }

    apr_table_set(r->subprocess_env, "REMOTE_USER", username);
    r->user = apr_pstrdup(r->pool, username);

    //ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Set REMOTE_USER = %s", username);

    return OK;
}

static void bearer_remote_user_register_hooks(apr_pool_t *p) {
    init_b64url_table();
    ap_hook_post_read_request(bearer_remote_user_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA bearer_remote_user_module = {
    STANDARD20_MODULE_STUFF,
    NULL, NULL, 
	create_jwt_remote_user_claim_config, 
	NULL,
    jwt_remote_user_claim_cmds,
    bearer_remote_user_register_hooks
};
