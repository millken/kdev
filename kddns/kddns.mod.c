#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x14522340, "module_layout" },
	{ 0x806e575f, "kmem_cache_destroy" },
	{ 0x5a34a45c, "__kmalloc" },
	{ 0xf9a482f9, "msleep" },
	{ 0x6980fe91, "param_get_int" },
	{ 0x25ec1b28, "strlen" },
	{ 0xd7c18d8f, "ip_local_out" },
	{ 0xd691cba2, "malloc_sizes" },
	{ 0x85df9b6c, "strsep" },
	{ 0xca975b7a, "nf_register_hook" },
	{ 0x999e8297, "vfree" },
	{ 0xff964b25, "param_set_int" },
	{ 0x3c2c5af5, "sprintf" },
	{ 0x47024ac3, "sysfs_remove_group" },
	{ 0x343a1a8, "__list_add" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x60ea2d6, "kstrtoull" },
	{ 0x45704798, "print_hex_dump_bytes" },
	{ 0xea147363, "printk" },
	{ 0xcf08c5b6, "kthread_stop" },
	{ 0x2d0bad1c, "sysfs_create_group" },
	{ 0xb4390f9a, "mcount" },
	{ 0x7329e40d, "kmem_cache_free" },
	{ 0xcb333fdc, "ip_route_me_harder" },
	{ 0x40a9b349, "vzalloc" },
	{ 0xee065ced, "kmem_cache_alloc" },
	{ 0x25421969, "__alloc_skb" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x3d75cbcf, "kfree_skb" },
	{ 0x266c7c38, "wake_up_process" },
	{ 0x2044fa9e, "kmem_cache_alloc_trace" },
	{ 0xe4a639f8, "kmem_cache_create" },
	{ 0xd2965f6f, "kthread_should_stop" },
	{ 0x7e5a6ea3, "nf_unregister_hook" },
	{ 0xcd04ab0b, "kernel_kobj" },
	{ 0x37a0cba, "kfree" },
	{ 0xc185e3ce, "kthread_create" },
	{ 0x236c8c64, "memcpy" },
	{ 0xe113bbbc, "csum_partial" },
	{ 0x207b7e2c, "skb_put" },
	{ 0xe914e41e, "strcpy" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "132EC2B3BA11EE55ADCDA49");

static const struct rheldata _rheldata __used
__attribute__((section(".rheldata"))) = {
	.rhel_major = 6,
	.rhel_minor = 5,
};
