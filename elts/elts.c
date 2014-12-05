#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
//#include <linux/smp_lock.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include "elts.h"
#include "hash.h"

#define MODULE_NAME "elts"

typedef  unsigned long  int  ub4;   /* unsigned 4-byte quantities */
typedef  unsigned       char ub1;   /* unsigned 1-byte quantities */

/** how many powers of 2's worth of buckets we use 
 *
 * For the moment, this is an important configuration value as the hash table
 * will never be resized.
 */
static unsigned int hashpower = 18;

#define hashsize(n) ((ub4)1<<(n))
#define hashmask(n) (hashsize(n)-1)

/** Main hash table. */
static item_t** primary_hashtable = 0;

/** Number of items in the hash table. */
static unsigned int hash_items = 0;

static DEFINE_MUTEX(storage_lock);

item_t* create_item(const char* domain, bool wild, bool exception)
{
    item_t* ret= kcalloc(1, sizeof(item_t), GFP_KERNEL);
    int ndomain = strlen(domain);

    if (ret != NULL){
        ret->domain= kmalloc(ndomain, GFP_KERNEL);

        if (ret->domain == NULL){
            kfree(ret->domain);
            kfree(ret);
            return NULL;
        }

        strcpy(ret->domain, domain);
        ret->ndomain = ndomain;
        ret->wild= wild;
        ret->exception= exception;
    }

    return ret;
}

item_t *get_item(const char* domain) 
{
    //mutex_lock(&storage_lock);
    int ndomain = strlen(domain);
    uint32_t hv = hash(domain, ndomain, 0);
    item_t *it, *ret = NULL;
    int depth = 0;

    it = primary_hashtable[hv & hashmask(hashpower)];

    while (it) {
        if ((ndomain == it->ndomain) && (memcmp(domain, it->domain, ndomain) == 0)) {
            ret = it;
            break;
        }
        it = it->h_next;
        ++depth;
    }
    //mutex_unlock(&storage_lock);
    return ret;
}

int add_domain(const char* domain, bool wild, bool exception)
{
    int rval;
    item_t* item = get_item(domain);

    if (item == NULL) {
        item= create_item(domain, wild, exception);
        if (item == NULL) {
            rval = 0x01;
        } else {
            put_item(item);
            rval = 0x00;
        }
    } else {
        rval= 0x02;
    }
    return rval;
}


/* Note: this isn't an update.  The key must not already exist to call this */
void put_item(item_t *it) 
{
    uint32_t hv;


    hv = hash(it->domain, it->ndomain, 0);

    it->h_next = primary_hashtable[hv & hashmask(hashpower)];
    primary_hashtable[hv & hashmask(hashpower)] = it;

    hash_items++;
}


void free_item(item_t* item)
{
    kfree(item->domain);
    kfree(item);
}

/** Purge ALL keys from the datastore
 *
 * TODO If provided, the when parameter specifies how far in the future the release
 * should occur.  Note that the release is not guarenteed to happen at this
 * time, only after it
 */
void flush(uint32_t when){
    int i;

    (void)when; //FIXME

    for(i = 0; i < hashsize(hashpower); i++){
        item_t *it = primary_hashtable[i], *next;
        while (it){
            next = it->h_next;
            free_item(it);
            it = next;
        }
        primary_hashtable[i] = NULL;
    }
}

bool initialize_storage(void) 
{
    primary_hashtable = vzalloc(hashsize(hashpower) * sizeof(void *));
    if (! primary_hashtable) {
        printk(KERN_INFO "assoc.c: Failed to init hashtable.\n");
        return false;
    }
    return true;
}

void test1(void) {
    item_t* item;
    add_domain("a.com", true, true);
    add_domain("a1.com", false, false);
    add_domain("a2.com",  false, true);
    add_domain("a3.com",  true, false);
    item = get_item("a.com");
    if (item != NULL) printk(KERN_INFO "item->domain=%s,item->wild=%d", item->domain, item->wild);
    item = get_item("a1.com");
    if (item != NULL) printk(KERN_INFO "item->domain=%s,item->wild=%d", item->domain, item->wild);    
    item = get_item("a4.com");
    if (item != NULL) printk(KERN_INFO "item->domain=%s,item->wild=%d", item->domain, item->wild);        
}

/* {{{ 查找字符串首次出现的位置，没有找到返回 -1，两个字符串相等返回 0
   在GCC下使用C99：
   int strpos(const char *haystack,const char *needle, _Bool ignorecase = 0)
   _Bool ignorecase =1 忽略大小写
   时间：2012-08-17 By Dewei 
*/
int strpos(const char *haystack, const char *needle, bool ignorecase)  
{  
    unsigned char c, needc;
    unsigned char const *from, *end;
    int len = strlen(haystack);
    int needlen = strlen(needle);
    int i = 0;
    const char *findreset;
    from = (unsigned char *)haystack;
    end = (unsigned char *)haystack + len;
    findreset = needle;
    for (i = 0; from < end; ++i) {
        c = *from++;
        needc = *needle;
        if (ignorecase) {
            if (c >= 65 && c < 97)
                c += 32;
            if (needc >= 65 && needc < 97)
                needc += 32;
        }
        if(c == needc) {
            ++needle;
            if(*needle == '\0') {
                if (len == needlen) 
                    return 0;
                else
                    return i - needlen+1;
            }
        }  
        else {  
            if(*needle == '\0' && needlen > 0)
                return i - needlen +1;
            needle = findreset;  
        }
    }  
    return  -1;  
}  



//from string
void test2(void) {
    item_t* item;
    char *str = "com.ac\nedu.ac\ngov.ac\ncom.cn";
const char*  delim = "\n";  
char *token, *cur = str;
char *domain;
bool wild , exception;
int i;

while ((token = strsep(&cur, delim))) {

    if ( (token[0] == '/' && token[1] == '/') || strpos(token, ".", true) == -1) continue;  
    wild = exception = false;

    domain = token;
    if(strpos(token, "!", true) == 0) {
        exception = true;
        strsep(&token, "!");
        domain = token;
    }
    if(strpos(token, "*.", true) == 0) {
        wild = true;
        strsep(&token, ".");
        domain = token;
    }
    add_domain(domain, wild, exception);
    printk(KERN_INFO "%s=%s\n", token, domain);  
  }

  for (i=0;i<3;i++)
    item = get_item("a.com");
    if (item != NULL) printk(KERN_INFO "item->domain=%s,item->wild=%d,item->exception=%d", item->domain, item->wild, item->exception);    

    item = get_item("com.cn");
    if (item != NULL) printk(KERN_INFO "item->domain=%s,item->wild=%d,item->exception=%d", item->domain, item->wild, item->exception);    

    item = get_item("com.cc");
    if (item != NULL) printk(KERN_INFO "item->domain=%s,item->wild=%d,item->exception=%d", item->domain, item->wild, item->exception);    


}



void shutdown_storage(void)
{
    flush(0);
    vfree(primary_hashtable);
}

/** Load the module */
int __init elts_init(void)
{

    if (initialize_storage() == false){
        printk(KERN_INFO MODULE_NAME": unable to initialize storage engine\n");
        return -ENOMEM;
        // FIXME leak in error condition
    }    
    test1();
    test2();
    printk(KERN_INFO MODULE_NAME": module loaded\n");
    return 0;
}

/** Unload the module 
 *
 */
void __exit elts_exit(void)
{

    shutdown_storage();
    printk(KERN_INFO MODULE_NAME": module unloaded\n");
}

/* init and cleanup functions */
module_init(elts_init);
module_exit(elts_exit);