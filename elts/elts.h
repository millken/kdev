#ifndef ELTS_H
#define ELTS_H

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

int add_domain(const char* domain, bool wild, bool exception);
//bool delete_item(const char* key, size_t nkey);

void free_item(item_t* item);
#endif
