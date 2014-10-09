

    /*
     * Kernel Send Udp packet Use userspace socket!
     *
     * This program is free software; you can redistribute it and/or modify
     * it under the terms of the GNU General Public License as published by
     * the Free Software Foundation; either version 2 of the License, or
     * (at your option) any later version.
     *
     * This program is distributed in the hope that it will be useful,
     * but WITHOUT ANY WARRANTY; without even the implied warranty of
     * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
     * GNU General Public License for more details.
     *
     * You should have received a copy of the GNU General Public License
     * along with this program; if not, write to the Free Software
     * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
     *
     * Copyright(C) Tony <tingw.liu@gmail.com> 2007-2013
     *        2013-07-04 08:09:07 CST
     */

    #include <linux/module.h>
    #include <linux/moduleparam.h>
    #include <linux/netfilter.h>
    #include <linux/ip.h>
    #include <net/tcp.h>
    #include <net/udp.h>
    #include <net/icmp.h>
    #include <linux/skbuff.h>
    #include <net/sock.h>
    #include <linux/net.h>
    #include <linux/inetdevice.h>
    #include <linux/in.h>
    #include <linux/kernel.h>
    #include <linux/types.h>
    #include <asm/unaligned.h>
    #include <linux/kthread.h>
    #include <linux/fdtable.h>
    #include <linux/file.h>

    MODULE_LICENSE("GPL");
    MODULE_AUTHOR("Tony <tingw.liu@gmail.com>");

    char *buffer = "Tony test from kernel!\n";
    module_param(buffer, charp, 0644);
    MODULE_PARM_DESC(buffer, "Packet content");

    pid_t pidnr = 1000;
    module_param(pidnr, int, 0644);
    MODULE_PARM_DESC(pidnr, "Process pid");

    int fd = 4;
    module_param(fd, int, 0644);
    MODULE_PARM_DESC(fd, "Socket file fd");

    long timeout = 1;
    module_param(timeout, long, 0644);
    MODULE_PARM_DESC(timeout, "Interval between send packets, default 1(unit second)");


    static struct task_struct *kthreadtask = NULL;

    struct file *sockfile = NULL;


    struct threadinfo{
        struct socket *sock;
        char *buffer;
    };

    static struct socket *sock_from_file(struct file *file, int *err)
    {
        /* FIXME: Warning....
         Because socket_file_ops is a static variable, so
         we can't check if the file is a socket like kernel
         function sock_from_file.
         So..., we doesn't check if the file is a socket and kernel
         will panic if the file is not a socket
         */


        //if (file->f_op == &socket_file_ops)
            return file->private_data;    /* set in sock_map_fd */

        *err = -ENOTSOCK;
        return NULL;
    }


    static struct socket *find_sock_by_pid_fd(pid_t pidnr, int fd, int *err)
    {
        struct task_struct *p;
        struct file *file;
        struct files_struct *files;
        struct socket *sock;
        struct pid *pid;
        pid = find_get_pid(pidnr);
        p = get_pid_task(pid, PIDTYPE_PID);
        if (!p) {
            printk(KERN_ALERT "find_task_by_vpid error!\n");
            return NULL;
        }


        /*
         Next code learn from fget()
         Because kernel fget() function use "current" variable,
         so rewrite
        */
        files = p->files;
        rcu_read_lock();
        file = fcheck_files(files, fd);
        if (file) {
            if (file->f_mode & FMODE_PATH || !atomic_long_inc_not_zero(&file->f_count))
                file = NULL;
        }
        rcu_read_unlock();
        if (!file) {
            printk(KERN_ALERT "Can't get file from fd\n");
            return NULL;
        }


        sockfile = file;
        sock = sock_from_file(sockfile, err);
        if (!sock) {
            fput(sockfile);
            sockfile = NULL;
        }
        return sock;
    }
    static int sendthread(void *data)
    {
        struct kvec iov;
        struct threadinfo *tinfo = data;
        struct msghdr msg = {.msg_flags = MSG_DONTWAIT|MSG_NOSIGNAL};
        int len;
        while (!kthread_should_stop()) {
            iov.iov_base = (void *)tinfo->buffer;
            iov.iov_len = strlen(tinfo->buffer);
            len = kernel_sendmsg(tinfo->sock, &msg, &iov, 1, strlen(tinfo->buffer));
            if (len != strlen(buffer)) {
                printk(KERN_ALERT "kernel_sendmsg err, len=%d, buffer=%d\n",
                        len, (int)strlen(buffer));
                if (len == -ECONNREFUSED) {
                    printk(KERN_ALERT "Receive Port Unreachable packet!\n");
                }
                break;
            }
            schedule_timeout_interruptible(timeout * HZ);
        }
        kthreadtask = NULL;
        kfree(tinfo);

        return 0;
    }

    static int __init udp_send_init(void)
    {
        int err = 0;
        struct socket *sock;
        struct threadinfo *tinfo;

        sock = find_sock_by_pid_fd(pidnr, fd, &err);    
        if (!sock) {
            printk(KERN_ALERT "find_sock error\n");
            goto find_error;
        }
        tinfo = kmalloc(sizeof(struct threadinfo), GFP_KERNEL);
        if (!tinfo) {
            printk(KERN_ALERT "kmalloc threadinfo err\n");
            goto kmalloc_error;
        }
        tinfo->sock = sock;
        tinfo->buffer = buffer;
        kthreadtask = kthread_run(sendthread, tinfo, "Tony-sendmsg");

        if (IS_ERR(kthreadtask)) {
            printk(KERN_ALERT "create sendmsg thread err, err=%ld\n",
                    PTR_ERR(kthreadtask));
            goto thread_error;
        }
        return 0;

    thread_error:
        kfree(tinfo);
    kmalloc_error:
        kthreadtask = NULL;
    find_error:
        return -1;
    }

    static void __exit udp_send_exit(void)
    {

        if (kthreadtask) {
            kthread_stop(kthreadtask);
        }

        if (sockfile) {
            fput(sockfile);
        }
        printk(KERN_ALERT "UDP send quit\n");

        return;
    }


    module_init(udp_send_init);
    module_exit(udp_send_exit);


