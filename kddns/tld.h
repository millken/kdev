#ifndef LTS_H
#define LTS_H

//http://mxr.mozilla.org/mozilla/source/netwerk/dns/src/nsEffectiveTLDService.h
typedef struct item {
  char  *domain;
  int   ndomain;
  bool  wild;
  bool	exception;
  struct item* h_next;
} item_t;

bool initialize_storage(void);
void shutdown_storage(void);

item_t* create_item(const char* domain, bool wild, bool exception);

void put_item(item_t* item);
item_t* get_item(const char* domain);
void free_item(item_t* item);
void flush(void);
int add_domain(const char* domain, bool wild, bool exception);
void load_tlds(void);
void test1(void);
int strpos(const char *haystack, const char *needle, bool ignorecase);
#endif
