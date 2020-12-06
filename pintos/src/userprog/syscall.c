#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}
static void
syscall_handler (struct intr_frame *f) 
{
  
  //printf ("system call!\n");
  
  if(*((int *)f->esp) == SYS_WRITE)
    sys_write(f);
  else if (*((int *)f->esp) == SYS_EXIT)
  {
    sys_exit(f);
  }
}
void
sys_exit(struct intr_frame* f){
  printf ("%s: exit(%d)\n",thread_name(), *(((int *)f->esp)+1));
  thread_exit();
}
void 
sys_write (struct intr_frame* f)
{
  int fd = *(((int *)f->esp) + 1);
  const char * buffer = (const char *)*(((int *)f->esp) + 2);
  size_t size = *(((int *)f->esp) + 3);
  if(fd == STDOUT_FILENO)
  	putbuf(buffer, size);

}

  
  

