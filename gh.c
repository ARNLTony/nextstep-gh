/*
 * GitHub CLI for NeXTSTEP
 * A native GitHub REST API client for NeXTSTEP 3.3
 *
 * Connects directly to api.github.com over TLS 1.2
 * using Crypto Ancienne (cryanc) by Cameron Kaiser.
 *
 * Build: cc -O -o gh gh.c
 * Usage: ./gh                       (reads .github_token)
 *        ./gh ghp_xxxxxxxxxxxx      (pass token directly)
 *
 * (c) 2026 ARNLTony & Claude. MIT License.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

/* Crypto Ancienne TLS library */
#include "cryanc.c"

/* --- Configuration --- */

#define API_HOST      "api.github.com"
#define API_PORT      443
#define TOKEN_FILE    ".github_token"

#define INPUT_BUF     1024
#define RESPONSE_BUF  131072  /* 128KB for list responses */
#define HTTP_BUF      4096
#define WRAP_WIDTH    72
#define PAGE_SIZE     30

/* --- Globals --- */

static char token[256];
static char default_owner[128];
static char default_repo[128];
static int running = 1;

/* Pagination state */
static char last_cmd[INPUT_BUF];
static int current_page = 1;
static int last_result_count = 0;

/* --- TLS helpers (from claude.c) --- */

int https_send_pending(sockfd, context)
int sockfd;
struct TLSContext *context;
{
    unsigned int out_buffer_len = 0;
    unsigned int out_buffer_index = 0;
    int send_res = 0;
    const unsigned char *out_buffer;

    out_buffer = tls_get_write_buffer(context, &out_buffer_len);
    while (out_buffer && out_buffer_len > 0) {
        int res = send(sockfd, (char *)&out_buffer[out_buffer_index],
                       out_buffer_len, 0);
        if (res <= 0) {
            send_res = res;
            break;
        }
        out_buffer_len -= res;
        out_buffer_index += res;
    }
    tls_buffer_clear(context);
    return send_res;
}

int validate_certificate(context, certificate_chain, len)
struct TLSContext *context;
struct TLSCertificate **certificate_chain;
int len;
{
    return no_error;
}

/* --- JSON helpers --- */

/*
 * Find a JSON string value by key. Returns pointer to start of value
 * (after opening quote), or NULL. Sets *out_len to length.
 */
char *json_find_string(json, key, out_len)
char *json;
char *key;
int *out_len;
{
    char pattern[256];
    char *p, *start, *search;

    sprintf(pattern, "\"%s\"", key);
    search = json;

    while (1) {
        p = strstr(search, pattern);
        if (!p) return NULL;

        p += strlen(pattern);

        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
            p++;

        if (*p != ':') {
            search = p;
            continue;
        }
        p++;

        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
            p++;

        if (*p != '"') {
            search = p;
            continue;
        }
        p++;
        start = p;

        while (*p && !(*p == '"' && *(p-1) != '\\'))
            p++;

        *out_len = p - start;
        return start;
    }
}

/*
 * Find a JSON number value by key. Returns the number, or -1 if not found.
 */
long json_find_number(json, key)
char *json;
char *key;
{
    char pattern[256];
    char *p, *search;
    long val;

    sprintf(pattern, "\"%s\"", key);
    search = json;

    while (1) {
        p = strstr(search, pattern);
        if (!p) return -1;

        p += strlen(pattern);

        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
            p++;

        if (*p != ':') {
            search = p;
            continue;
        }
        p++;

        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
            p++;

        if (*p == '-' || (*p >= '0' && *p <= '9')) {
            val = atol(p);
            return val;
        }

        search = p;
    }
}

/*
 * Find a JSON boolean value by key. Returns 1 for true, 0 for false, -1 if not found.
 */
int json_find_bool(json, key)
char *json;
char *key;
{
    char pattern[256];
    char *p, *search;

    sprintf(pattern, "\"%s\"", key);
    search = json;

    while (1) {
        p = strstr(search, pattern);
        if (!p) return -1;

        p += strlen(pattern);

        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
            p++;

        if (*p != ':') {
            search = p;
            continue;
        }
        p++;

        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
            p++;

        if (strncmp(p, "true", 4) == 0) return 1;
        if (strncmp(p, "false", 5) == 0) return 0;

        search = p;
    }
}

/* --- JSON array iterator --- */

/*
 * Find the first element in a JSON array.
 * json should point to the opening '['.
 * Returns pointer to start of first object, or NULL if empty.
 * Sets *end to one past the closing '}' of the element.
 */
char *json_array_first(json, end)
char *json;
char **end;
{
    char *p;
    int depth;

    p = json;
    while (*p && *p != '[') p++;
    if (!*p) return NULL;
    p++; /* skip '[' */

    /* skip whitespace */
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;

    if (*p == ']') return NULL; /* empty array */
    if (*p != '{') return NULL; /* we only handle arrays of objects */

    /* find matching closing brace */
    depth = 0;
    *end = p;
    while (**end) {
        if (**end == '{') depth++;
        else if (**end == '}') {
            depth--;
            if (depth == 0) {
                (*end)++;
                return p;
            }
        } else if (**end == '"') {
            /* skip strings to avoid counting braces inside them */
            (*end)++;
            while (**end && !(**end == '"' && *(*end - 1) != '\\'))
                (*end)++;
        }
        (*end)++;
    }
    return NULL;
}

/*
 * Find the next element after *end in a JSON array.
 * Returns pointer to start of next object, or NULL if no more.
 * Updates *end to one past the closing '}' of the element.
 */
char *json_array_next(pos, end)
char *pos;
char **end;
{
    char *p;
    int depth;

    p = *end;

    /* skip whitespace */
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;

    if (*p != ',') return NULL; /* no more elements */
    p++; /* skip comma */

    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;

    if (*p != '{') return NULL;

    depth = 0;
    *end = p;
    while (**end) {
        if (**end == '{') depth++;
        else if (**end == '}') {
            depth--;
            if (depth == 0) {
                (*end)++;
                return p;
            }
        } else if (**end == '"') {
            (*end)++;
            while (**end && !(**end == '"' && *(*end - 1) != '\\'))
                (*end)++;
        }
        (*end)++;
    }
    return NULL;
}

/* --- JSON unescape helper --- */

void json_unescape(src, src_len, dst, dst_size)
char *src;
int src_len;
char *dst;
int dst_size;
{
    int i, j;

    j = 0;
    for (i = 0; i < src_len && j < dst_size - 1; i++) {
        if (src[i] == '\\' && i + 1 < src_len) {
            i++;
            switch (src[i]) {
                case 'n':  dst[j++] = '\n'; break;
                case 't':  dst[j++] = '\t'; break;
                case '"':  dst[j++] = '"';  break;
                case '\\': dst[j++] = '\\'; break;
                case '/':  dst[j++] = '/';  break;
                default:   dst[j++] = src[i]; break;
            }
        } else {
            dst[j++] = src[i];
        }
    }
    dst[j] = '\0';
}

/* --- Base64 decoder --- */

static char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int b64_val(c)
int c;
{
    char *p;
    if (c == '=') return 0;
    p = strchr(b64_table, c);
    if (!p) return -1;
    return p - b64_table;
}

/*
 * Decode base64 data in-place (or to a separate buffer).
 * Skips whitespace in input. Returns decoded length.
 */
int gh_base64_decode(src, src_len, dst, dst_size)
char *src;
int src_len;
char *dst;
int dst_size;
{
    int i, j, a, b, c, d;

    j = 0;
    i = 0;
    while (i < src_len && j < dst_size - 1) {
        /* skip whitespace and newlines */
        while (i < src_len && (src[i] == '\n' || src[i] == '\r' ||
               src[i] == ' ' || src[i] == '\t' || src[i] == '\\'))
        {
            /* skip literal \n in JSON strings */
            if (src[i] == '\\' && i + 1 < src_len && src[i+1] == 'n') {
                i += 2;
            } else {
                i++;
            }
        }
        if (i + 3 >= src_len) break;

        a = b64_val(src[i]);
        b = b64_val(src[i+1]);
        c = b64_val(src[i+2]);
        d = b64_val(src[i+3]);
        if (a < 0 || b < 0 || c < 0 || d < 0) { i += 4; continue; }

        if (j < dst_size - 1) dst[j++] = (a << 2) | (b >> 4);
        if (src[i+2] != '=' && j < dst_size - 1) dst[j++] = ((b & 0x0F) << 4) | (c >> 2);
        if (src[i+3] != '=' && j < dst_size - 1) dst[j++] = ((c & 0x03) << 6) | d;
        i += 4;
    }
    dst[j] = '\0';
    return j;
}

/* --- JSON string escape for POST bodies --- */

void json_escape(src, dst, dst_size)
char *src;
char *dst;
int dst_size;
{
    int i, j;

    j = 0;
    for (i = 0; src[i] && j < dst_size - 2; i++) {
        switch (src[i]) {
            case '"':  dst[j++] = '\\'; dst[j++] = '"';  break;
            case '\\': dst[j++] = '\\'; dst[j++] = '\\'; break;
            case '\n': dst[j++] = '\\'; dst[j++] = 'n';  break;
            case '\t': dst[j++] = '\\'; dst[j++] = 't';  break;
            default:   dst[j++] = src[i]; break;
        }
    }
    dst[j] = '\0';
}

/* --- Display helpers --- */

void print_wrapped(prefix, text, width)
char *prefix;
char *text;
int width;
{
    int col, prefix_len, i;
    char *p;

    prefix_len = strlen(prefix);
    printf("%s", prefix);
    col = prefix_len;

    p = text;
    while (*p) {
        if (*p == '\n') {
            putchar('\n');
            for (i = 0; i < prefix_len; i++) putchar(' ');
            col = prefix_len;
            p++;
            continue;
        }

        if (col >= width && *p == ' ') {
            putchar('\n');
            for (i = 0; i < prefix_len; i++) putchar(' ');
            col = prefix_len;
            p++;
            continue;
        }

        putchar(*p);
        col++;
        p++;
    }
    putchar('\n');
}

/* Print a short string field from a JSON object, with label */
void print_field(json, key, label)
char *json;
char *key;
char *label;
{
    char *val;
    int len;
    char buf[512];

    val = json_find_string(json, key, &len);
    if (val && len > 0) {
        if (len > (int)sizeof(buf) - 1) len = sizeof(buf) - 1;
        json_unescape(val, len, buf, sizeof(buf));
        printf("  %s: %s\n", label, buf);
    }
}

/* --- Core HTTP engine --- */

/*
 * Make a GitHub API request. method is "GET" or "POST".
 * path is the API path (e.g., "/repos/octocat/Hello-World").
 * post_body is the JSON body for POST, or NULL for GET.
 * response buffer receives the raw JSON body.
 * Returns 0 on success, -1 on error.
 */
int github_request(method, path, post_body, response, response_size)
char *method;
char *path;
char *post_body;
char *response;
int response_size;
{
    int sockfd;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    struct TLSContext *context;
    char *http_request;
    int req_len, body_len;
    char *resp_data;
    int resp_len;
    int read_size;
    int sent;
    char *body_start;
    char *status_line;
    int status_code;
    unsigned char tls_buf[HTTP_BUF];

    body_len = post_body ? strlen(post_body) : 0;

    /* Build HTTP request */
    http_request = (char *)malloc(body_len + 2048);
    if (!http_request) {
        strcpy(response, "Out of memory");
        return -1;
    }

    if (post_body) {
        sprintf(http_request,
            "%s %s HTTP/1.0\r\n"
            "Host: %s\r\n"
            "Authorization: Bearer %s\r\n"
            "User-Agent: github-nextstep/1.0\r\n"
            "Accept: application/vnd.github+json\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n"
            "\r\n"
            "%s",
            method, path, API_HOST, token, body_len, post_body);
    } else {
        sprintf(http_request,
            "%s %s HTTP/1.0\r\n"
            "Host: %s\r\n"
            "Authorization: Bearer %s\r\n"
            "User-Agent: github-nextstep/1.0\r\n"
            "Accept: application/vnd.github+json\r\n"
            "Connection: close\r\n"
            "\r\n",
            method, path, API_HOST, token);
    }
    req_len = strlen(http_request);

    /* Resolve hostname */
    printf("  Connecting...\r");
    fflush(stdout);

    server = gethostbyname(API_HOST);
    if (!server) {
        free(http_request);
        strcpy(response, "DNS lookup failed");
        return -1;
    }

    /* Create socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        free(http_request);
        strcpy(response, "Socket creation failed");
        return -1;
    }

    memset((char *)&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy((char *)&serv_addr.sin_addr.s_addr,
           (char *)server->h_addr, server->h_length);
    serv_addr.sin_port = htons(API_PORT);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        free(http_request);
        close(sockfd);
        strcpy(response, "Connection failed");
        return -1;
    }

    /* TLS handshake */
    printf("  TLS handshake...\r");
    fflush(stdout);

    context = tls_create_context(0, TLS_V12);
    if (!context || !tls_sni_set(context, API_HOST)) {
        free(http_request);
        close(sockfd);
        strcpy(response, "TLS setup failed");
        return -1;
    }
    tls_client_connect(context);
    https_send_pending(sockfd, context);

    /* Complete handshake and send request */
    sent = 0;
    resp_data = (char *)malloc(response_size);
    if (!resp_data) {
        free(http_request);
        tls_destroy_context(context);
        close(sockfd);
        strcpy(response, "Out of memory");
        return -1;
    }
    resp_len = 0;

    while (1) {
        read_size = recv(sockfd, (char *)tls_buf, sizeof(tls_buf), 0);
        if (read_size <= 0) break;

        tls_consume_stream(context, tls_buf, read_size,
                           validate_certificate);
        https_send_pending(sockfd, context);

        if (!tls_established(context))
            continue;

        if (!sent) {
            printf("  Waiting...    \r");
            fflush(stdout);
            tls_write(context, (unsigned char *)http_request, req_len);
            https_send_pending(sockfd, context);
            sent = 1;
        }

        while ((read_size = tls_read(context, tls_buf, sizeof(tls_buf) - 1)) > 0) {
            if (resp_len + read_size < response_size - 1) {
                memcpy(resp_data + resp_len, tls_buf, read_size);
                resp_len += read_size;
            }
        }
    }

    resp_data[resp_len] = '\0';
    free(http_request);
    tls_destroy_context(context);
    close(sockfd);

    /* Check HTTP status */
    status_code = 0;
    status_line = strstr(resp_data, "HTTP/");
    if (status_line) {
        char *sp = strchr(status_line, ' ');
        if (sp) status_code = atoi(sp + 1);
    }

    /* Skip HTTP headers */
    body_start = strstr(resp_data, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        strncpy(response, body_start, response_size - 1);
        response[response_size - 1] = '\0';
    } else {
        strncpy(response, resp_data, response_size - 1);
        response[response_size - 1] = '\0';
    }

    printf("                \r"); /* clear status line */
    fflush(stdout);

    free(resp_data);

    if (status_code >= 400) {
        char *msg;
        int msg_len;
        char err[512];

        msg = json_find_string(response, "message", &msg_len);
        if (msg && msg_len > 0) {
            if (msg_len > (int)sizeof(err) - 1) msg_len = sizeof(err) - 1;
            json_unescape(msg, msg_len, err, sizeof(err));
            printf("  Error %d: %s\n", status_code, err);
        } else {
            printf("  Error %d\n", status_code);
        }
        return -1;
    }

    return 0;
}

/* --- Command helpers --- */

/*
 * Parse "owner/repo" from a string. Returns 0 on success.
 */
int parse_owner_repo(str, owner, repo)
char *str;
char *owner;
char *repo;
{
    char *slash;
    int owner_len;

    slash = strchr(str, '/');
    if (!slash) return -1;

    owner_len = slash - str;
    if (owner_len <= 0 || owner_len > 127) return -1;
    if (strlen(slash + 1) == 0 || strlen(slash + 1) > 127) return -1;

    strncpy(owner, str, owner_len);
    owner[owner_len] = '\0';
    strcpy(repo, slash + 1);

    /* strip trailing whitespace from repo */
    while (strlen(repo) > 0 && (repo[strlen(repo)-1] == ' ' ||
           repo[strlen(repo)-1] == '\t'))
        repo[strlen(repo)-1] = '\0';

    return 0;
}

int require_repo()
{
    if (default_owner[0] == '\0') {
        printf("  No repo set. Use: repo owner/repo\n");
        return -1;
    }
    return 0;
}

/* --- Command handlers --- */

void cmd_help()
{
    printf("\n");
    printf("  Commands:\n");
    printf("    repo owner/repo    Set default repo and show info\n");
    printf("    repos [user]       List user's repos\n");
    printf("    issues             List open issues\n");
    printf("    issue N            View issue detail\n");
    printf("    create \"title\" \"body\"  Create new issue\n");
    printf("    pulls              List open pull requests\n");
    printf("    cat path           View file contents\n");
    printf("    next               Next page of results\n");
    printf("    help               Show this help\n");
    printf("    quit               Exit\n");
    printf("\n");
}

void cmd_repos(username, page)
char *username;
int page;
{
    char path[512];
    char *response;
    char *elem, *end;
    char name[256], desc[512];
    char *val;
    int len, count;
    long stars;

    response = (char *)malloc(RESPONSE_BUF);
    if (!response) { printf("  Out of memory\n"); return; }

    sprintf(path, "/users/%s/repos?sort=updated&per_page=%d&page=%d",
            username, PAGE_SIZE, page);

    if (github_request("GET", path, NULL, response, RESPONSE_BUF) < 0) {
        free(response);
        return;
    }

    count = 0;
    elem = json_array_first(response, &end);
    while (elem) {
        count++;
        val = json_find_string(elem, "full_name", &len);
        if (val && len > 0 && len < (int)sizeof(name) - 1) {
            json_unescape(val, len, name, sizeof(name));
        } else {
            strcpy(name, "???");
        }

        stars = json_find_number(elem, "stargazers_count");

        val = json_find_string(elem, "description", &len);
        if (val && len > 0) {
            if (len > (int)sizeof(desc) - 1) len = sizeof(desc) - 1;
            json_unescape(val, len, desc, sizeof(desc));
        } else {
            desc[0] = '\0';
        }

        printf("  %s", name);
        if (stars > 0) printf(" (*%ld)", stars);
        printf("\n");
        if (desc[0]) {
            print_wrapped("    ", desc, WRAP_WIDTH);
        }

        elem = json_array_next(elem, &end);
    }

    if (count == 0) {
        printf("  No repos found.\n");
    } else {
        printf("  --- %d repos", count);
        if (count == PAGE_SIZE) printf(" (more may exist, use 'next')");
        printf(" ---\n");
    }

    last_result_count = count;
    free(response);
}

void cmd_repo_info(owner, repo)
char *owner;
char *repo;
{
    char path[512];
    char *response;
    long num;

    response = (char *)malloc(RESPONSE_BUF);
    if (!response) { printf("  Out of memory\n"); return; }

    sprintf(path, "/repos/%s/%s", owner, repo);

    if (github_request("GET", path, NULL, response, RESPONSE_BUF) < 0) {
        free(response);
        return;
    }

    printf("\n");
    print_field(response, "full_name", "Repo");
    print_field(response, "description", "Desc");
    print_field(response, "language", "Lang");
    print_field(response, "default_branch", "Branch");

    num = json_find_number(response, "stargazers_count");
    if (num >= 0) printf("  Stars: %ld\n", num);

    num = json_find_number(response, "forks_count");
    if (num >= 0) printf("  Forks: %ld\n", num);

    num = json_find_number(response, "open_issues_count");
    if (num >= 0) printf("  Open issues: %ld\n", num);

    if (json_find_bool(response, "fork") == 1)
        printf("  (fork)\n");
    if (json_find_bool(response, "private") == 1)
        printf("  (private)\n");

    printf("\n");
    free(response);
}

void cmd_issues(page)
int page;
{
    char path[512];
    char *response;
    char *elem, *end;
    char title[512], *val;
    int len, count;
    long num;

    if (require_repo() < 0) return;

    response = (char *)malloc(RESPONSE_BUF);
    if (!response) { printf("  Out of memory\n"); return; }

    sprintf(path, "/repos/%s/%s/issues?state=open&per_page=%d&page=%d",
            default_owner, default_repo, PAGE_SIZE, page);

    if (github_request("GET", path, NULL, response, RESPONSE_BUF) < 0) {
        free(response);
        return;
    }

    count = 0;
    elem = json_array_first(response, &end);
    while (elem) {
        count++;
        num = json_find_number(elem, "number");

        val = json_find_string(elem, "title", &len);
        if (val && len > 0) {
            if (len > (int)sizeof(title) - 1) len = sizeof(title) - 1;
            json_unescape(val, len, title, sizeof(title));
        } else {
            strcpy(title, "???");
        }

        printf("  #%ld  %s\n", num, title);

        elem = json_array_next(elem, &end);
    }

    if (count == 0) {
        printf("  No open issues.\n");
    } else {
        printf("  --- %d issues", count);
        if (count == PAGE_SIZE) printf(" (use 'next' for more)");
        printf(" ---\n");
    }

    last_result_count = count;
    free(response);
}

void cmd_issue(number)
int number;
{
    char path[512];
    char *response;
    char body_buf[4096];
    char *val;
    int len;

    if (require_repo() < 0) return;

    response = (char *)malloc(RESPONSE_BUF);
    if (!response) { printf("  Out of memory\n"); return; }

    sprintf(path, "/repos/%s/%s/issues/%d", default_owner, default_repo, number);

    if (github_request("GET", path, NULL, response, RESPONSE_BUF) < 0) {
        free(response);
        return;
    }

    printf("\n");
    printf("  Issue #%ld\n", json_find_number(response, "number"));
    print_field(response, "title", "Title");
    print_field(response, "state", "State");

    /* print user login from nested object - search for "login" after "user" */
    val = json_find_string(response, "user", &len);
    if (val) {
        /* back up to find the { of the user object, then find login within it */
        char *user_obj = strstr(response, "\"user\"");
        if (user_obj) {
            char *login = json_find_string(user_obj, "login", &len);
            if (login && len > 0) {
                char login_buf[128];
                if (len > (int)sizeof(login_buf) - 1) len = sizeof(login_buf) - 1;
                json_unescape(login, len, login_buf, sizeof(login_buf));
                printf("  Author: %s\n", login_buf);
            }
        }
    }

    print_field(response, "created_at", "Created");

    printf("\n");

    val = json_find_string(response, "body", &len);
    if (val && len > 0) {
        if (len > (int)sizeof(body_buf) - 1) len = sizeof(body_buf) - 1;
        json_unescape(val, len, body_buf, sizeof(body_buf));
        print_wrapped("  ", body_buf, WRAP_WIDTH);
    } else {
        printf("  (no description)\n");
    }
    printf("\n");

    free(response);
}

void cmd_create(title, body)
char *title;
char *body;
{
    char path[512];
    char *response;
    char *post_body;
    char esc_title[1024];
    char esc_body[4096];
    long num;

    if (require_repo() < 0) return;

    json_escape(title, esc_title, sizeof(esc_title));
    json_escape(body, esc_body, sizeof(esc_body));

    post_body = (char *)malloc(strlen(esc_title) + strlen(esc_body) + 128);
    if (!post_body) { printf("  Out of memory\n"); return; }

    sprintf(post_body, "{\"title\":\"%s\",\"body\":\"%s\"}", esc_title, esc_body);

    response = (char *)malloc(RESPONSE_BUF);
    if (!response) { free(post_body); printf("  Out of memory\n"); return; }

    sprintf(path, "/repos/%s/%s/issues", default_owner, default_repo);

    if (github_request("POST", path, post_body, response, RESPONSE_BUF) < 0) {
        free(post_body);
        free(response);
        return;
    }

    num = json_find_number(response, "number");
    if (num > 0) {
        printf("  Created issue #%ld\n", num);
    } else {
        printf("  Issue created (could not read number)\n");
    }

    free(post_body);
    free(response);
}

void cmd_pulls(page)
int page;
{
    char path[512];
    char *response;
    char *elem, *end;
    char title[512], *val;
    int len, count;
    long num;

    if (require_repo() < 0) return;

    response = (char *)malloc(RESPONSE_BUF);
    if (!response) { printf("  Out of memory\n"); return; }

    sprintf(path, "/repos/%s/%s/pulls?state=open&per_page=%d&page=%d",
            default_owner, default_repo, PAGE_SIZE, page);

    if (github_request("GET", path, NULL, response, RESPONSE_BUF) < 0) {
        free(response);
        return;
    }

    count = 0;
    elem = json_array_first(response, &end);
    while (elem) {
        count++;
        num = json_find_number(elem, "number");

        val = json_find_string(elem, "title", &len);
        if (val && len > 0) {
            if (len > (int)sizeof(title) - 1) len = sizeof(title) - 1;
            json_unescape(val, len, title, sizeof(title));
        } else {
            strcpy(title, "???");
        }

        printf("  #%ld  %s\n", num, title);

        elem = json_array_next(elem, &end);
    }

    if (count == 0) {
        printf("  No open pull requests.\n");
    } else {
        printf("  --- %d PRs", count);
        if (count == PAGE_SIZE) printf(" (use 'next' for more)");
        printf(" ---\n");
    }

    last_result_count = count;
    free(response);
}

void cmd_cat(filepath)
char *filepath;
{
    char path[512];
    char *response;
    char *val;
    int len;
    char *decoded;
    int decoded_len;

    if (require_repo() < 0) return;

    response = (char *)malloc(RESPONSE_BUF);
    if (!response) { printf("  Out of memory\n"); return; }

    sprintf(path, "/repos/%s/%s/contents/%s", default_owner, default_repo, filepath);

    if (github_request("GET", path, NULL, response, RESPONSE_BUF) < 0) {
        free(response);
        return;
    }

    /* Check encoding */
    val = json_find_string(response, "encoding", &len);
    if (!val || strncmp(val, "base64", 6) != 0) {
        printf("  File too large or unsupported encoding.\n");
        free(response);
        return;
    }

    /* Get base64 content */
    val = json_find_string(response, "content", &len);
    if (!val || len == 0) {
        printf("  No content found.\n");
        free(response);
        return;
    }

    decoded = (char *)malloc(len);
    if (!decoded) {
        printf("  Out of memory\n");
        free(response);
        return;
    }

    decoded_len = gh_base64_decode(val, len, decoded, len);
    printf("\n%s\n", decoded);

    free(decoded);
    free(response);
}

/* --- Quoted string parser for create command --- */

/*
 * Parse a quoted string from input, advancing *pos past the closing quote.
 * Returns pointer to static buffer with the unquoted content, or NULL.
 */
char *parse_quoted(pos)
char **pos;
{
    static char buf[2048];
    char *p, *start;
    int i;

    p = *pos;

    /* skip whitespace */
    while (*p == ' ' || *p == '\t') p++;

    if (*p != '"') return NULL;
    p++; /* skip opening quote */
    start = p;

    i = 0;
    while (*p && *p != '"' && i < (int)sizeof(buf) - 1) {
        buf[i++] = *p++;
    }
    buf[i] = '\0';

    if (*p == '"') p++; /* skip closing quote */
    *pos = p;

    return buf;
}

/* --- Command dispatcher --- */

void dispatch_command(input)
char *input;
{
    char *cmd, *arg;

    /* skip leading whitespace */
    cmd = input;
    while (*cmd == ' ' || *cmd == '\t') cmd++;

    if (*cmd == '\0') return;

    /* find end of command word */
    arg = cmd;
    while (*arg && *arg != ' ' && *arg != '\t') arg++;
    if (*arg) {
        *arg = '\0';
        arg++;
        while (*arg == ' ' || *arg == '\t') arg++;
    }

    /* --- Dispatch --- */

    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "?") == 0) {
        cmd_help();
    }
    else if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0) {
        running = 0;
    }
    else if (strcmp(cmd, "repo") == 0) {
        char owner[128], repo[128];
        if (parse_owner_repo(arg, owner, repo) < 0) {
            printf("  Usage: repo owner/repo\n");
            return;
        }
        strcpy(default_owner, owner);
        strcpy(default_repo, repo);
        cmd_repo_info(owner, repo);
    }
    else if (strcmp(cmd, "repos") == 0) {
        if (*arg == '\0') {
            printf("  Usage: repos username\n");
            return;
        }
        /* strip trailing whitespace */
        {
            int alen = strlen(arg);
            while (alen > 0 && (arg[alen-1] == ' ' || arg[alen-1] == '\t'
                   || arg[alen-1] == '\n' || arg[alen-1] == '\r'))
                arg[--alen] = '\0';
        }
        strcpy(last_cmd, input); /* won't work because we modified it */
        sprintf(last_cmd, "repos %s", arg);
        current_page = 1;
        cmd_repos(arg, 1);
    }
    else if (strcmp(cmd, "issues") == 0) {
        sprintf(last_cmd, "issues");
        current_page = 1;
        cmd_issues(1);
    }
    else if (strcmp(cmd, "issue") == 0) {
        int num = atoi(arg);
        if (num <= 0) {
            printf("  Usage: issue N\n");
            return;
        }
        cmd_issue(num);
    }
    else if (strcmp(cmd, "create") == 0) {
        char *title, *body;
        char *pos = arg;

        title = parse_quoted(&pos);
        if (!title) {
            printf("  Usage: create \"title\" \"body\"\n");
            return;
        }
        /* copy title since parse_quoted uses static buffer */
        {
            char title_copy[2048];
            strcpy(title_copy, title);

            body = parse_quoted(&pos);
            if (!body) {
                cmd_create(title_copy, "");
            } else {
                cmd_create(title_copy, body);
            }
        }
    }
    else if (strcmp(cmd, "pulls") == 0) {
        sprintf(last_cmd, "pulls");
        current_page = 1;
        cmd_pulls(1);
    }
    else if (strcmp(cmd, "cat") == 0) {
        if (*arg == '\0') {
            printf("  Usage: cat path/to/file\n");
            return;
        }
        /* strip trailing whitespace */
        {
            int alen = strlen(arg);
            while (alen > 0 && (arg[alen-1] == ' ' || arg[alen-1] == '\t'
                   || arg[alen-1] == '\n' || arg[alen-1] == '\r'))
                arg[--alen] = '\0';
        }
        cmd_cat(arg);
    }
    else if (strcmp(cmd, "next") == 0) {
        if (last_cmd[0] == '\0') {
            printf("  No previous list command to continue.\n");
            return;
        }
        if (last_result_count < PAGE_SIZE) {
            printf("  No more results.\n");
            return;
        }
        current_page++;
        /* re-dispatch based on last command */
        if (strncmp(last_cmd, "repos ", 6) == 0) {
            cmd_repos(last_cmd + 6, current_page);
        } else if (strcmp(last_cmd, "issues") == 0) {
            cmd_issues(current_page);
        } else if (strcmp(last_cmd, "pulls") == 0) {
            cmd_pulls(current_page);
        } else {
            printf("  Cannot paginate last command.\n");
        }
    }
    else {
        printf("  Unknown command: %s (type 'help' for commands)\n", cmd);
    }
}

/* --- Token loading --- */

int load_token()
{
    FILE *fp;
    int len;
    char path[512];
    char *home;

    /* Try current directory first */
    fp = fopen(TOKEN_FILE, "r");
    if (!fp) {
        /* Try home directory */
        home = getenv("HOME");
        if (home) {
            sprintf(path, "%s/%s", home, TOKEN_FILE);
            fp = fopen(path, "r");
        }
    }

    if (!fp) return -1;

    if (fgets(token, sizeof(token), fp) == NULL) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    /* Strip newline */
    len = strlen(token);
    while (len > 0 && (token[len-1] == '\n' || token[len-1] == '\r'))
        token[--len] = '\0';

    return (len > 0) ? 0 : -1;
}

/* --- Signal handler --- */

void handle_sigint(sig)
int sig;
{
    printf("\n\n  Goodbye!\n\n");
    running = 0;
}

/* --- Main --- */

int main(argc, argv)
int argc;
char **argv;
{
    char input[INPUT_BUF];

    signal(SIGINT, handle_sigint);

    /* Load token */
    if (argc > 1 && strncmp(argv[1], "ghp_", 4) == 0) {
        strncpy(token, argv[1], sizeof(token) - 1);
    } else if (argc > 1 && strncmp(argv[1], "github_pat_", 11) == 0) {
        strncpy(token, argv[1], sizeof(token) - 1);
    } else if (load_token() != 0) {
        printf("\n  GitHub CLI for NeXTSTEP\n\n");
        printf("  Token not found. Create a file called '%s'\n", TOKEN_FILE);
        printf("  containing your GitHub personal access token, or pass it as\n");
        printf("  an argument:\n\n");
        printf("    ./gh ghp_xxxxxxxxxxxx\n\n");
        return 1;
    }

    /* Initialize */
    default_owner[0] = '\0';
    default_repo[0] = '\0';
    last_cmd[0] = '\0';
    current_page = 1;
    last_result_count = 0;

    printf("\n");
    printf("  GitHub CLI for NeXTSTEP\n");
    printf("  Type 'help' for commands, 'quit' to exit.\n");
    printf("\n");

    /* Main REPL loop */
    while (running) {
        if (default_owner[0])
            printf("github:%s/%s> ", default_owner, default_repo);
        else
            printf("github> ");
        fflush(stdout);

        if (fgets(input, sizeof(input), stdin) == NULL)
            break;

        /* Strip newline */
        {
            int len = strlen(input);
            while (len > 0 && (input[len-1] == '\n' || input[len-1] == '\r'))
                input[--len] = '\0';
        }

        if (input[0] == '\0')
            continue;

        dispatch_command(input);
    }

    printf("\n  Goodbye!\n\n");
    return 0;
}
