#define ETH_ALEN	6		/* Octets in one ethernet addr	 */
struct atk_info
{
	unsigned char	eth_dst[ETH_ALEN];	
	unsigned int	dst_ip;			/*Ä¿±êµØÖ·*/
	unsigned short	dst_port;
	unsigned int	src_ip;
	unsigned short	src_port;
	unsigned int	degree;
	unsigned char domain[255];
	unsigned int atk_type;
};
#define DNS_FLOOD	1
#define	SYN_FLOOD	2
#define ATK_STATE	3
#define BIG_FLOOD	4
#define ADD_ADDR	5
#define LST_LEVEL	6
#define LST_CLEAN	7
#define LST_DEFAULT	8
