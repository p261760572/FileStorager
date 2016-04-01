struct mg_request_info 
{
	void *user_data;       // User-defined pointer passed to mg_start()
	char *request_method;  // "GET", "POST", etc
	char *uri;             // URL-decoded URI
	char *http_version;    // E.g. "1.0", "1.1"
	char *query_string;    // URL part after '?' (not including '?') or NULL
	char *remote_user;     // Authenticated user, or NULL if no auth used
	char *log_message;     // Mongoose error log message, MG_EVENT_LOG only
	long remote_ip;        // Client's IP address
	int remote_port;       // Client's port
	int status_code;       // HTTP reply status code, e.g. 200
	int is_ssl;            // 1 if SSL-ed, 0 if not
	int num_headers;       // Number of headers
	struct mg_header 
	{
		char *name;          // HTTP header name
		char *value;         // HTTP header value
	}http_headers[64];    // Maximum 64 headers
};

int get_request_len(const char *buf, int buflen);
int parse_http_request(char *buf, struct mg_request_info *ri);
const char *get_header(const struct mg_request_info *ri,const char *name);