#ifndef LTS_H
#define LTS_H



void initialize_storage(void);
void shutdown_storage(void);
struct item_t* get_item(const char* domain);
void load_tlds(void);

#endif
