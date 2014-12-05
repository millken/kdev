#include <linux/types.h>
/*H(k) = k%p
 *@ p<=m,m哈希表的长度
*/
#define NR_HASH 13 /*m*/
#define P 13 /*p*/
#define NR_KEYS 12 /*keys number*/

#define hashfn(x) ((x)%(P)) /*hashfn*/

int keys[NR_KEYS] = {19, 14, 23, 01, 68, 20, 84, 27, 55, 11, 10, 79}; /*关键字
*/

struct hash_term /*哈希表项*/
{
        int key;
        struct hlist_node list;
};
struct hlist_head hash[NR_HASH]; /*哈希表*/
