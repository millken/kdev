#include <linux/types.h>
/*H(k) = k%p
 *@ p<=m,m哈希表的长度
*/
#define NR_HASH 18 /*m*/
#define P 18 /*p*/
#define NR_KEYS 12 /*keys number*/

#define hashfn(x) ((x)%(P)) /*hashfn*/

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

int keys[NR_KEYS] = {19, 14, 23, 01, 68, 20, 84, 27, 55, 11, 10, 79}; /*关键字
*/

struct hash_term /*哈希表项*/
{
		char key[70];
        struct hlist_node list;
};
struct hlist_head hash_powers[NR_HASH]; /*哈希表*/
