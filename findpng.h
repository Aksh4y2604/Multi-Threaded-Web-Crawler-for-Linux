
#include <libxml/HTMLparser.h>
#include <libxml/parser.h>
#include <libxml/uri.h>
#include <libxml/xpath.h>
#define max(a, b)           \
  ({                        \
    __typeof__(a) _a = (a); \
    __typeof__(b) _b = (b); \
    _a > _b ? _a : _b;      \
  })

typedef struct recv_buf2 {
  char* buf;       /* memory to hold a copy of received data */
  size_t size;     /* size of valid data in buf in bytes*/
  size_t max_size; /* max capacity of buf in bytes*/
  int seq;         /* >=0 sequence number extracted from http header */
                   /* <0 indicates an invalid seq number */
} RECV_BUF;

int in_hash(char* url);
int is_png(RECV_BUF* file);
htmlDocPtr mem_getdoc(char* buf, int size, const char* url);
xmlXPathObjectPtr getnodeset(xmlDocPtr doc, xmlChar* xpath);
int find_http(char* fname,
              int size,
              int follow_relative_links,
              const char* base_url);
size_t header_cb_curl(char* p_recv, size_t size, size_t nmemb, void* userdata);
size_t write_cb_curl3(char* p_recv,
                      size_t size,
                      size_t nmemb,
                      void* p_userdata);
int recv_buf_init(RECV_BUF* ptr, size_t max_size);
int recv_buf_cleanup(RECV_BUF* ptr);
void cleanup(CURL* curl, RECV_BUF* ptr);
int write_file(const char* path, const void* in, size_t len);
CURL* easy_handle_init(RECV_BUF* ptr, const char* url);
int process_data(CURL* curl_handle, RECV_BUF* p_recv_buf);
void check_url(const char* url);
void* thread(void* ignore);
void thread_cleanup(void* arg);