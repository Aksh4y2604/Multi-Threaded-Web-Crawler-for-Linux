/*
 * The code is derived from cURL example and paster.c base code.
 * The cURL example is at URL:
 * https://curl.haxx.se/libcurl/c/getinmemory.html
 * Copyright (C) 1998 - 2018, Daniel Stenberg, <daniel@haxx.se>, et al..
 *
 * The xml example code is
 * http://www.xmlsoft.org/tutorial/ape.html
 *
 * The paster.c code is
 * Copyright 2013 Patrick Lam, <p23lam@uwaterloo.ca>.
 *
 * Modifications to the code are
 * Copyright 2018-2019, Yiqing Huang, <yqhuang@uwaterloo.ca>.
 *
 * This software may be freely redistributed under the terms of the X11 license.
 */

/**
 * @file main_wirte_read_cb.c
 * @brief cURL write call back to save received data in a user defined memory
 * first and then write the data to a file for verification purpose. cURL header
 * call back extracts data sequence number from header if there is a sequence
 * number.
 * @see https://curl.haxx.se/libcurl/c/getinmemory.html
 * @see https://curl.haxx.se/libcurl/using/
 * @see https://ec.haxx.se/callback-write.html
 */

#include <curl/curl.h>

#include <pthread.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "findpng.h"
#define SEED_URL "http://ece252-1.uwaterloo.ca/lab4"
#define ECE252_HEADER "X-Ece252-Fragment: "
#define BUF_SIZE 1048576 /* 1024*1024 = 1M */
#define BUF_INC 524288   /* 1024*512  = 0.5M */
#define URL_SPACES 10000
char string_space[URL_SPACES * 20]; /* Space to store strings. */
char* str_ptr = string_space;       /* Next space in string_space. */

#define CT_PNG "image/png"
#define CT_HTML "text/html"
#define CT_PNG_LEN 9
#define CT_HTML_LEN 9
typedef unsigned char U8;

/**
 * @brief  declaration of global variables
 **/
pthread_mutex_t num_images_m;
int images_found;
int images_to_find = 50;

pthread_mutex_t mutex;
int num_threads = 1;

pthread_mutex_t num_m;
pthread_mutex_t images_found_m;
int url_on = 0;
char* log_file_name = "";
char* png_urls = "png_urls.txt";
char* urls[100000];
int url_num = 0;

/**
 * @brief  insert a url into the hash table
 * @param  char *url: the url to be inserted
 * @return void
 **/
void insert_hash(char* url) {
  ENTRY item;
  item.key = url;
  str_ptr += strlen(url) + 1;

  /* Put item into table. */
  (void)hsearch(item, ENTER);
}

/**
 * @brief  check if the url is already in the hash table
 * @param  char *url: the url to be checked
 * @return 1 if the url is in the hash table, 0 otherwise
 **/

int in_hash(char* url) {
  ENTRY item;
  ENTRY* found_item; /* Name to look for in table. */
  /* Access table. */
  item.key = url;
  if ((found_item = hsearch(item, FIND)) != NULL) {
    /* If item is in the table. */
    return 1;
  }
  return 0;
}

/**
 * @brief  check if the data is a non-corrupted png
 * @param  RECV_BUF *file: the data to be checked
 * @return 1 if the data is a png, 0 otherwise
 **/

int is_png(RECV_BUF* file) {
  U8 header[9];
  memcpy(header, file->buf, 4);

  if (header[0] == 0x89 && header[1] == 0x50 && header[2] == 0x4e &&
      header[3] == 0x47) {
    return 1;
  }
  return 0;
}

/**
 * @brief  parse the data into a html document
 * @param  char *buf: the data to be parsed
 * @param  int size: the size of the data
 * @param  const char *url: the url of the data
 * @return htmlDocPtr: the parsed html document
 **/
htmlDocPtr mem_getdoc(char* buf, int size, const char* url) {
  int opts = HTML_PARSE_NOBLANKS | HTML_PARSE_NOERROR | HTML_PARSE_NOWARNING |
             HTML_PARSE_NONET;
  htmlDocPtr doc = htmlReadMemory(buf, size, url, NULL, opts);

  if (doc == NULL) {
    // fprintf(stderr, "Document not parsed successfully.\n");
    return NULL;
  }
  return doc;
}

xmlXPathObjectPtr getnodeset(xmlDocPtr doc, xmlChar* xpath) {
  xmlXPathContextPtr context;
  xmlXPathObjectPtr result;

  context = xmlXPathNewContext(doc);
  if (context == NULL) {
    printf("Error in xmlXPathNewContext\n");
    return NULL;
  }
  result = xmlXPathEvalExpression(xpath, context);
  xmlXPathFreeContext(context);
  if (result == NULL) {
    printf("Error in xmlXPathEvalExpression\n");
    return NULL;
  }
  if (xmlXPathNodeSetIsEmpty(result->nodesetval)) {
    xmlXPathFreeObject(result);
    // printf("No result\n");
    return NULL;
  }
  return result;
}

/**
 * @brief  find all the http links in the html document
 * @param  char *buf: the data to be parsed
 * @param  int size: the size of the data
 * @param  int follow_relative_links: whether to follow relative links
 * @param  const char *base_url: the base url of the data
 * @return 0 on success, -1 on failure
 **/
int find_http(char* buf,
              int size,
              int follow_relative_links,
              const char* base_url) {
  int i;
  htmlDocPtr doc;
  xmlChar* xpath = (xmlChar*)"//a/@href";
  xmlNodeSetPtr nodeset;
  xmlXPathObjectPtr result;
  xmlChar* href;

  //   printf("base_url: %s\n", base_url);

  if (buf == NULL) {
    return 1;
  }
  pthread_mutex_lock(&mutex);
  doc = mem_getdoc(buf, size, base_url);
  result = getnodeset(doc, xpath);
  if (result) {
    nodeset = result->nodesetval;
    for (i = 0; i < nodeset->nodeNr; i++) {
      href = xmlNodeListGetString(doc, nodeset->nodeTab[i]->xmlChildrenNode, 1);
      if (follow_relative_links) {
        xmlChar* old = href;
        href = xmlBuildURI(href, (xmlChar*)base_url);
        xmlFree(old);
      }

      if (href != NULL && !strncmp((const char*)href, "http", 4)) {
        // printf("href: %s\n", href);
        // add link to a table
        // printf("total searches: %d \n", total_searches);

        // need to check if url is already in urls or not
        if (!in_hash((char*)href)) {
          insert_hash((char*)href);
          urls[url_num] = (char*)href;
          // paste the url into the log file
          if (strcmp(log_file_name, "") != 0) {
            FILE* fp = fopen(log_file_name, "a");
            if (fp == NULL) {
              perror("fopen");
              return -2;
            }
            fprintf(fp, "%s\n", href);
            fclose(fp);
          }
          // printf("url %s added at pos %d \n", urls[url_num], url_num);
          url_num++;
        } else {
          xmlFree(href);
        }
      } else {
        xmlFree(href);
      }

      // xmlFree(href);
    }
    xmlXPathFreeObject(result);
  }
  xmlFreeDoc(doc);
  xmlCleanupParser();
  pthread_mutex_unlock(&mutex);
  return 0;
}
/**
 * @brief  cURL header call back function to extract image sequence number from
 *         http header data. An example header for image part n (assume n = 2)
 * is: X-Ece252-Fragment: 2
 * @param  char *p_recv: header data delivered by cURL
 * @param  size_t size size of each memb
 * @param  size_t nmemb number of memb
 * @param  void *userdata user defined data structurea
 * @return size of header data received.
 * @details this routine will be invoked multiple times by the libcurl until the
 * full header data are received.  we are only interested in the ECE252_HEADER
 * line received so that we can extract the image sequence number from it. This
 * explains the if block in the code.
 */
size_t header_cb_curl(char* p_recv, size_t size, size_t nmemb, void* userdata) {
  int realsize = size * nmemb;
  RECV_BUF* p = userdata;

#ifdef DEBUG1_
  // printf("%s", p_recv);
#endif /* DEBUG1_ */
  if (realsize > strlen(ECE252_HEADER) &&
      strncmp(p_recv, ECE252_HEADER, strlen(ECE252_HEADER)) == 0) {
    /* extract img sequence number */
    p->seq = atoi(p_recv + strlen(ECE252_HEADER));
  }
  return realsize;
}

/**
 * @brief write callback function to save a copy of received data in RAM.
 *        The received libcurl data are pointed by p_recv,
 *        which is provided by libcurl and is not user allocated memory.
 *        The user allocated memory is at p_userdata. One needs to
 *        cast it to the proper struct to make good use of it.
 *        This function maybe invoked more than once by one invokation of
 *        curl_easy_perform().
 */

size_t write_cb_curl3(char* p_recv,
                      size_t size,
                      size_t nmemb,
                      void* p_userdata) {
  size_t realsize = size * nmemb;
  RECV_BUF* p = (RECV_BUF*)p_userdata;

  if (p->size + realsize + 1 > p->max_size) { /* hope this rarely happens */
    /* received data is not 0 terminated, add one byte for terminating 0 */
    size_t new_size = p->max_size + max(BUF_INC, realsize + 1);
    char* q = realloc(p->buf, new_size);
    if (q == NULL) {
      perror("realloc"); /* out of memory */
      return -1;
    }
    p->buf = q;
    p->max_size = new_size;
  }

  memcpy(p->buf + p->size, p_recv, realsize); /*copy data from libcurl*/
  p->size += realsize;
  p->buf[p->size] = 0;

  return realsize;
}

/**
 * @brief initialize a RECV_BUF structure
 * @param ptr RECV_BUF *, pointer to a RECV_BUF structure
 * @param max_size size_t, max size of the buffer
 * @return 0 on success; non-zero otherwise
 */
int recv_buf_init(RECV_BUF* ptr, size_t max_size) {
  void* p = NULL;

  if (ptr == NULL) {
    return 1;
  }

  p = malloc(max_size);
  if (p == NULL) {
    return 2;
  }

  ptr->buf = p;
  ptr->size = 0;
  ptr->max_size = max_size;
  ptr->seq = -1; /* valid seq should be positive */
  return 0;
}

/**
 * @brief clean up a RECV_BUF structure
 * @param ptr RECV_BUF *, pointer to a RECV_BUF structure
 * @return 0 on success; non-zero otherwise
 */
int recv_buf_cleanup(RECV_BUF* ptr) {
  if (ptr == NULL) {
    return 1;
  }

  free(ptr->buf);
  ptr->size = 0;
  ptr->max_size = 0;
  return 0;
}

/**
 * @brief clean up curl and user defined data structure
 * @param curl CURL *, pointer to a curl easy handle
 * @param ptr RECV_BUF *, pointer to a RECV_BUF structure
 * @return void
 */
void cleanup(CURL* curl, RECV_BUF* ptr) {
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  recv_buf_cleanup(ptr);
}

/**
 * @brief output data in memory to a file
 * @param path const char *, output file path
 * @param in  void *, input data to be written to the file
 * @param len size_t, length of the input data in bytes
 */
int write_file(const char* path, const void* in, size_t len) {
  FILE* fp = NULL;

  if (path == NULL) {
    fprintf(stderr, "write_file: file name is null!\n");
    return -1;
  }

  if (in == NULL) {
    fprintf(stderr, "write_file: input data is null!\n");
    return -1;
  }

  fp = fopen(path, "wb");
  if (fp == NULL) {
    perror("fopen");
    return -2;
  }

  if (fwrite(in, 1, len, fp) != len) {
    fprintf(stderr, "write_file: imcomplete write!\n");
    return -3;
  }
  return fclose(fp);
}

/**
 * @brief create a curl easy handle and set the options.
 * @param RECV_BUF *ptr points to user data needed by the curl write call back
 * function
 * @param const char *url is the target url to fetch resoruce
 * @return a valid CURL * handle upon sucess; NULL otherwise
 * Note: the caller is responsbile for cleaning the returned curl handle
 */
CURL* easy_handle_init(RECV_BUF* ptr, const char* url) {
  CURL* curl_handle = NULL;

  if (ptr == NULL || url == NULL) {
    return NULL;
  }

  /* init user defined call back function buffer */
  if (recv_buf_init(ptr, BUF_SIZE) != 0) {
    return NULL;
  }
  /* init a curl session */
  curl_handle = curl_easy_init();

  if (curl_handle == NULL) {
    fprintf(stderr, "curl_easy_init: returned NULL\n");
    return NULL;
  }

  /* specify URL to get */
  curl_easy_setopt(curl_handle, CURLOPT_URL, url);

  /* register write call back function to process received data */
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_cb_curl3);
  /* user defined data structure passed to the call back function */
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void*)ptr);

  /* register header call back function to process received header data */
  curl_easy_setopt(curl_handle, CURLOPT_HEADERFUNCTION, header_cb_curl);
  /* user defined data structure passed to the call back function */
  curl_easy_setopt(curl_handle, CURLOPT_HEADERDATA, (void*)ptr);

  /* some servers requires a user-agent field */
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "ece252 lab4 crawler");

  /* follow HTTP 3XX redirects */
  curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
  /* continue to send authentication credentials when following locations */
  curl_easy_setopt(curl_handle, CURLOPT_UNRESTRICTED_AUTH, 1L);
  /* max numbre of redirects to follow sets to 5 */
  curl_easy_setopt(curl_handle, CURLOPT_MAXREDIRS, 5L);
  /* supports all built-in encodings */
  curl_easy_setopt(curl_handle, CURLOPT_ACCEPT_ENCODING, "");

  /* Max time in seconds that the connection phase to the server to take */
  // curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, 5L);
  /* Max time in seconds that libcurl transfer operation is allowed to take */
  // curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 10L);
  /* Time out for Expect: 100-continue response in milliseconds */
  // curl_easy_setopt(curl_handle, CURLOPT_EXPECT_100_TIMEOUT_MS, 0L);

  /* Enable the cookie engine without reading any initial cookies */
  curl_easy_setopt(curl_handle, CURLOPT_COOKIEFILE, "");
  /* allow whatever auth the proxy speaks */
  curl_easy_setopt(curl_handle, CURLOPT_PROXYAUTH, CURLAUTH_ANY);
  /* allow whatever auth the server speaks */
  curl_easy_setopt(curl_handle, CURLOPT_HTTPAUTH, CURLAUTH_ANY);

  return curl_handle;
}

/**
 * @brief process the html data by curl
 * @param CURL *curl_handle is the curl handler
 * @param RECV_BUF p_recv_buf contains the received data.
 * @return 0 on success; non-zero otherwise
 */
int process_html(CURL* curl_handle, RECV_BUF* p_recv_buf) {
  char fname[256];
  int follow_relative_link = 1;
  char* url = NULL;
  pid_t pid = getpid();

  curl_easy_getinfo(curl_handle, CURLINFO_EFFECTIVE_URL, &url);
  find_http(p_recv_buf->buf, p_recv_buf->size, follow_relative_link, url);
  sprintf(fname, "./output_%d.html", pid);
  return write_file(fname, p_recv_buf->buf, p_recv_buf->size);
}

/**
 * @brief process the png data by curl
 * @param CURL *curl_handle is the curl handler
 * @param RECV_BUF p_recv_buf contains the received data.
 * @return 0 on success; non-zero otherwise
 */
int process_png(CURL* curl_handle, RECV_BUF* p_recv_buf) {
  // check if it's a real image or not
  if (!is_png(p_recv_buf)) {
    return 0;
  }
  pthread_mutex_lock(&images_found_m);
  if (images_found > images_to_find - 1) {
    pthread_mutex_unlock(&images_found_m);
    return 0;
  } else {
    pthread_mutex_unlock(&images_found_m);
  }
  pid_t pid = getpid();
  char fname[256];
  char* eurl = NULL; /* effective URL */
  curl_easy_getinfo(curl_handle, CURLINFO_EFFECTIVE_URL, &eurl);

  if (eurl != NULL) {
    FILE* fp = fopen(png_urls, "a");
    if (fp == NULL) {
      perror("fopen");
      return -2;
    }
    fprintf(fp, "%s\n", eurl);
    fclose(fp);
    // printf("The PNG url is: %s\n", eurl);
  }

  sprintf(fname, "./output_%d_%d.png", p_recv_buf->seq, pid);
  pthread_mutex_lock(&num_images_m);
  images_found++;
  pthread_mutex_unlock(&num_images_m);
  return write_file(fname, p_recv_buf->buf, p_recv_buf->size);
}
/**
 * @brief process the download data by curl
 * @param CURL *curl_handle is the curl handler
 * @param RECV_BUF p_recv_buf contains the received data.
 * @return 0 on success; non-zero otherwise
 */
int process_data(CURL* curl_handle, RECV_BUF* p_recv_buf) {
  CURLcode res;
  // char fname[256];
  // pid_t pid = getpid();
  long response_code;
  res = curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &response_code);
  if (res == CURLE_OK) {
    // printf("Response code: %ld\n", response_code);
  }

  if (response_code >= 400) {
    // fprintf(stderr, "Error.\n");
    return 1;
  }

  char* ct = NULL;
  res = curl_easy_getinfo(curl_handle, CURLINFO_CONTENT_TYPE, &ct);
  if (res == CURLE_OK && ct != NULL) {
    // printf("Content-Type: %s, len=%ld\n", ct, strlen(ct));
  } else {
    fprintf(stderr, "Failed obtain Content-Type\n");
    return 2;
  }

  if (strstr(ct, CT_HTML)) {
    return process_html(curl_handle, p_recv_buf);
  } else if (strstr(ct, CT_PNG)) {
    return process_png(curl_handle, p_recv_buf);
  }
  // else {
  //   sprintf(fname, "./output_%d", pid);
  // }
  return 0;
  // return write_file(fname, p_recv_buf->buf, p_recv_buf->size);
}

/**
 * @brief  fetch the url and check if it's a png
 * @param  char *url: the url to be checked
 **/
void check_url(const char* url) {
  CURL* curl_handle;
  CURLcode res;
  RECV_BUF recv_buf;

  curl_global_init(CURL_GLOBAL_DEFAULT);
  curl_handle = easy_handle_init(&recv_buf, url);

  if (curl_handle == NULL) {
    fprintf(stderr, "Curl initialization failed. Exiting...\n");
    curl_global_cleanup();
    return;
  }
  /* get it! */
  res = curl_easy_perform(curl_handle);

  if (res != CURLE_OK) {
    // fprintf(stderr, "curl_easy_perform() failed: %s\n",
    // curl_easy_strerror(res));
    // printf("url value: %s\n", url);
    cleanup(curl_handle, &recv_buf);
    // exit(1);
    return;
  } else {
    // printf("%lu bytes received in memory %p, seq=%d.\n", recv_buf.size,
    //    recv_buf.buf, recv_buf.seq);
  }

  /* process the download data */
  process_data(curl_handle, &recv_buf);

  /* cleaning up */
  cleanup(curl_handle, &recv_buf);
  return;
}

/**
 * @brief  main function for the thread
 * @param  void *ignore: required for pthread_create
 **/

void* thread(void* _ignore) {
  pthread_cleanup_push(thread_cleanup, NULL);
  int local_url_on = 0;
  int local_url_num = url_num;
  int local_images_found = 0;
  pthread_mutex_lock(&num_m);
  local_images_found = images_found;
  pthread_mutex_unlock(&num_m);
  while ((local_images_found < images_to_find)) {
    pthread_mutex_lock(&num_m);
    local_url_on = url_on;
    local_images_found = images_found;
    if (local_images_found > images_to_find) {
      pthread_cancel(pthread_self());
    }
    while (local_url_on >= local_url_num) {
      pthread_mutex_lock(&num_images_m);
      local_images_found = images_found;
      pthread_mutex_unlock(&num_images_m);
      if (local_images_found >= images_to_find) {
        break;
      }
      pthread_mutex_lock(&mutex);
      local_url_num = url_num;
      pthread_mutex_unlock(&mutex);
    }

    url_on++;
    pthread_mutex_unlock(&num_m);
    if (local_url_on < local_url_num) {
      pthread_mutex_lock(&mutex);
      const char* url = urls[local_url_on];
      pthread_mutex_unlock(&mutex);
      printf("-searching %s at pos %d, url_num=%d\n", url, local_url_on,
             local_url_num);
      check_url((const char*)url);
    }
  }

  pthread_cleanup_pop(0);
  return NULL;
}

/**
 * @brief  clean up the thread
 * @param  void *arg: required for pthread_cleanup_push
 **/
void thread_cleanup(void* arg) {
  pthread_mutex_unlock(&mutex);
  pthread_mutex_unlock(&num_m);
}

int main(int argc, char** argv) {
  char url[256];

  /* get options */
  int t = 0;
  int m = 0;
  // char* v = 0;

  int opt;
  while ((opt = getopt(argc, argv, "t:m:v:")) != -1) {
    switch (opt) {
      case 't':
        t = atoi(optarg);
        num_threads = t;
        break;
      case 'm':
        m = atoi(optarg);
        images_to_find = m;
        break;
      case 'v':
        log_file_name = optarg;
        break;
    }
  }
  if (strcmp(log_file_name, "") != 0) {
    FILE* fp = fopen(log_file_name, "w");
    fclose(fp);
  }
  FILE* fp = fopen(png_urls, "w");
  fclose(fp);

  if (optind >= argc) {
    strcpy(url, SEED_URL);
  } else {
    strncpy(url, argv[optind], sizeof(url));
    url[sizeof(url) - 1] = '\0';
  }
  // printf("%s: URL is %s\n", argv[0], url);
  if (strcmp(log_file_name, "") != 0) {
    FILE* fp = fopen(log_file_name, "a");
    if (fp == NULL) {
      perror("fopen");
      return -2;
    }
    fprintf(fp, "%s\n", url);
    fclose(fp);
  }
  /* setup timing parameters */
  struct timeval tv;
  double times[2];

  if (gettimeofday(&tv, NULL) != 0) {
    perror("gettimeofday");
    abort();
  }
  times[0] = (tv.tv_sec) + tv.tv_usec / 1000000.;

  /* create a hash table to store urls */
  (void)hcreate(URL_SPACES);

  urls[0] = url;
  url_num++;
  insert_hash(url);

  if (images_to_find > 50) {
    images_to_find = 50;
  }
  images_found = 0;

  pthread_mutex_init(&mutex, NULL);
  pthread_mutex_init(&num_m, NULL);
  pthread_mutex_init(&num_images_m, NULL);
  pthread_mutex_init(&images_found_m, NULL);

  pthread_t threads[num_threads];
  for (int i = 0; i < num_threads; ++i) {
    pthread_create(&threads[i], NULL, thread, NULL);
  }

  for (int k = 0; k < num_threads; k++) {
    pthread_join(threads[k], NULL);
  }

  // printf("Found a total of %d images\n", images_found);
  // printf("Found a total of %d urls\n", url_num);

  for (int i = 1; i < url_num; i++) {
    xmlFree(urls[i]);
  }

  pthread_mutex_destroy(&mutex);
  pthread_mutex_destroy(&num_m);
  pthread_mutex_destroy(&num_images_m);
  pthread_mutex_destroy(&images_found_m);
  hdestroy();

  if (gettimeofday(&tv, NULL) != 0) {
    perror("gettimeofday");
    abort();
  }
  times[1] = (tv.tv_sec) + tv.tv_usec / 1000000.;
  printf("findpng2 execution time: %f seconds\n", times[1] - times[0]);
  return 0;
}
