#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/security.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/dcache.h>

#include <linux/file.h>

//include for the read/write semaphore
#include <linux/rwsem.h>

//needed for set_memory_rw
#include <asm/cacheflush.h>

#include "offsets.h"

//These two definitions and the one for set_addr_rw and ro are from
// http://stackoverflow.com/questions/2103315/linux-kernel-system-call-hooking-example
#define GPF_DISABLE() write_cr0(read_cr0() & (~0x10000))
#define GPF_ENABLE() write_cr0(read_cr0() | 0x10000)

//seed@ubuntu:~/Downloads/hw5$ sudo grep sys_call_table /proc/kallsyms
//c1513160 R sys_call_table
static long* sys_call_table = (long*)SYS_CALL_TABLE_ADDR;

typedef asmlinkage long (* sys_open_func_ptr)(const char __user* filename, int flags, int mode);

sys_open_func_ptr sys_open_orig = NULL;


typedef asmlinkage long (* sys_read_func_ptr)(unsigned int fd, char __user* buf, size_t count);

sys_read_func_ptr sys_read_orig = NULL;

typedef asmlinkage long (* sys_write_func_ptr)(unsigned int fd, char __user* buf, size_t count);

sys_write_func_ptr sys_write_orig = NULL;


static struct rw_semaphore myrwsema;

#define STRLEN 1024
char kernel_buf[STRLEN];
int len = 0;

//http://creativeandcritical.net/str-replace-c/
//modified by tuananh to work with kernel space
char *replace_str(const char *str, const char *old, const char *new)
{
	char *ret, *r;
	const char *p, *q;
	size_t oldlen = strlen(old);
	size_t count, retlen, newlen = strlen(new);

	if (oldlen != newlen) {
		for (count = 0, p = str; (q = strstr(p, old)) != NULL; p = q + oldlen)
			count++;
		/* this is undefined if p - str > PTRDIFF_MAX */
		retlen = p - str + strlen(p) + count * (newlen - oldlen);
	} else
		retlen = strlen(str);

	if ((ret = vmalloc(retlen + 1)) == NULL)
		return NULL;

	for (r = ret, p = str; (q = strstr(p, old)) != NULL; p = q + oldlen) {
		/* this is undefined if q - p > PTRDIFF_MAX */
		ptrdiff_t l = q - p;
		memcpy(r, p, l);
		r += l;
		memcpy(r, new, newlen);
		r += newlen;
	}
	strcpy(r, p);

	return ret;
}

//don't forget the asmlinkage declaration. This is a particular calling convention
asmlinkage long my_sys_open(const char __user* filename, int flags, int mode)
{
  long ret = 0;
  char* tmp = NULL;

  //add in another reader to the semaphore
  down_read(&myrwsema);

  ret = sys_open_orig(filename, flags, mode);

  tmp = getname(filename); //this is needed because filename is in userspace
  if (tmp) {
    if (strcmp(tmp, "SECRET.TXT") == 0) {
        printk(KERN_INFO "The file [%s] is being opened\n", tmp);
    } else if (strstr(tmp, "/SECRET.TXT")) {
        if (strcmp(strstr(tmp, "/SECRET.TXT"), "/SECRET.TXT") == 0)
        printk(KERN_INFO "The file [%s] is being opened\n", tmp);
    }
  }

  //release the reader lock (or one of them) right before the return
  // to limit the possibility of unloading the module
  // when there is still code to be executed
  up_read(&myrwsema);
  return (ret);
}

asmlinkage long my_sys_read(unsigned int fd, char __user* buf, size_t count)
{
  long ret = 0;
  struct file* file;
  
  down_read(&myrwsema);

  ret = sys_read_orig(fd, buf, count);
  
  //if the current file is SECRET.TXT
  //ignore stdin, stdout and stderr
  if (fd > 2) {
    file = fget(fd);
    if (file) {
      if (strcmp(file->f_dentry->d_name.name, "SECRET.TXT") == 0){
        memset(kernel_buf, 0, STRLEN);
        if (count > STRLEN) {
          len = STRLEN-1;
        } else {
          len = count;
        }
        copy_from_user(kernel_buf, buf, len);
        printk(KERN_INFO "[%s] is being read from SECRET.TXT\n", buf);
      }
    }
  }

  up_read(&myrwsema);
  return (ret);
}

asmlinkage long my_sys_write(unsigned int fd, char __user* buf, size_t count)
{
  long ret = 0;
  struct file* file;
  char* modified_buf;
  
  down_read(&myrwsema);
  
  //if the current file is SECRET.TXT
  //ignore stdin, stdout and stderr
  if (fd > 2) {
    file = fget(fd);
    if (file) {
      if (strcmp(file->f_dentry->d_name.name, "SECRET.TXT") == 0){
        memset(kernel_buf, 0, STRLEN);
        if (count > STRLEN) {
          len = STRLEN-1;
        } else {
          len = count;
        }
        copy_from_user(kernel_buf, buf, len);
        modified_buf = replace_str(kernel_buf, "HELLO", "HELLOhooked");
        printk("REPLACED: %s", modified_buf);
        count = strlen(modified_buf);
        copy_to_user(buf, modified_buf, count);
        fput(file);
      }
    }
  }
  
  ret = sys_write_orig(fd, buf, count);

  up_read(&myrwsema);
  return (ret);
}

int set_addr_rw(unsigned long addr)
{
  unsigned int level; 
  pte_t* pte = lookup_address(addr, &level);
  if (pte == NULL)
  {
    return (-1);
  }

  pte->pte |= _PAGE_RW;

  return (0);
}

int set_addr_ro(unsigned long addr)
{
  unsigned int level; 
  pte_t* pte = lookup_address(addr, &level);
  if (pte == NULL)
  {
    return (-1);
  }

  pte->pte = pte->pte & ~_PAGE_RW;

  return (0);
}

int init_module(void)
{
  //sys_close is exported, so we can use it to make sure we have the
  // right address for sys_call_table
  //printk(KERN_INFO "sys_close is at [%p] == [%p]?.\n", sys_call_table[__NR_close], &sys_close);
  if (sys_call_table[__NR_close] != (long)(&sys_close))
  {
    printk(KERN_INFO "Seems like we don't have the right addresses [0x%08lx] vs [%p]\n", sys_call_table[__NR_close], &sys_close);
    return (-1); 
  }

  //initialize the rw semahore
  init_rwsem(&myrwsema);

  //make sure the table is writable
  set_addr_rw( (unsigned long)sys_call_table);
  //GPF_DISABLE();

  printk(KERN_INFO "Saving sys_open @ [0x%08lx]\n", sys_call_table[__NR_open]);
  sys_open_orig = (sys_open_func_ptr)(sys_call_table[__NR_open]);
  sys_call_table[__NR_open] = (long)&my_sys_open;

  printk(KERN_INFO "Saving sys_read @ [0x%08lx]\n", sys_call_table[__NR_read]);
  sys_read_orig = (sys_read_func_ptr)(sys_call_table[__NR_read]);
  sys_call_table[__NR_read] = (long)&my_sys_read;
  
  printk(KERN_INFO "Saving sys_write @ [0x%08lx]\n", sys_call_table[__NR_write]);
  sys_write_orig = (sys_write_func_ptr)(sys_call_table[__NR_write]);
  sys_call_table[__NR_write] = (long)&my_sys_write;

  set_addr_ro( (unsigned long)sys_call_table);
  //GPF_ENABLE();

  return (0);
}

void cleanup_module(void)
{
  if (sys_open_orig != NULL)
  {
    set_addr_rw( (unsigned long)sys_call_table);

    printk(KERN_INFO "Restoring sys_open\n");
    sys_call_table[__NR_open] = (long)sys_open_orig; 

    printk(KERN_INFO "Restoring sys_read\n");
    sys_call_table[__NR_read] = (long)sys_read_orig; 
    
    printk(KERN_INFO "Restoring sys_write\n");
    sys_call_table[__NR_write] = (long)sys_write_orig; 

    set_addr_ro( (unsigned long)sys_call_table);
  }

  //after the system call table has been restored - we will need to wait
  printk(KERN_INFO "Checking the semaphore as a write ...\n");
  down_write(&myrwsema);
  
  printk(KERN_INFO "Have the write lock - meaning all read locks have been released\n");
  printk(KERN_INFO " So it is now safe to remove the module\n");
}

MODULE_LICENSE("GPL");
