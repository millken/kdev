#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

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

bool initialize_storage(void) 
{
    primary_hashtable = vzalloc(hashsize(hashpower) * sizeof(void *));
    if (! primary_hashtable) {
        printk(KERN_INFO "assoc.c: Failed to init hashtable.\n");
        return false;
    }
    return true;
}

void shutdown_storage(void)
{
    flush(0);
    vfree(primary_hashtable);
}


item_t* create_item(const char* domain, size_t ndomain, bool wild, bool exception)
{
    item_t* ret= kcalloc(1, sizeof(item_t), GFP_KERNEL);

    if (ret != NULL){
        ret->domain= kmalloc(ndomain, GFP_KERNEL);

        if (ret->domain == NULL){
            kfree(ret->domain);
            kfree(ret);
            return NULL;
        }

        memcpy(ret->domain, domain, ndomain);
        ret->ndomain = ndomain;
        ret->wild= wild;
        ret->exception= exception;
    }

    return ret;
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

/** Load the module */
int __init elts_init(void)
{

    if (initialize_storage() == false){
        printk(KERN_INFO MODULE_NAME": unable to initialize storage engine\n");
        return -ENOMEM;
        // FIXME leak in error condition
    }    
    printk(KERN_INFO MODULE_NAME": module loaded\n");
    return 0;
}

/** Unload the module 
 *
 */
void __exit elts_exit(void){

    printk(KERN_INFO MODULE_NAME": module unloaded\n");
}

/* init and cleanup functions */
module_init(elts_init);
module_exit(elts_exit);