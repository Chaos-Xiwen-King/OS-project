#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <devices/shutdown.h>
#include <string.h>
#include <filesys/file.h>
#include <devices/input.h>
#include <threads/malloc.h>
#include <threads/palloc.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"
#include "pagedir.h"
#include <threads/vaddr.h>
#include <filesys/filesys.h>

void sys_halt(struct intr_frame* f);
void sys_exit(struct intr_frame* f);
void sys_exec(struct intr_frame* f);
void sys_create(struct intr_frame* f);
void sys_remove(struct intr_frame* f);
void sys_open(struct intr_frame* f);
void sys_wait(struct intr_frame* f);
void sys_filesize(struct intr_frame* f);
void sys_read(struct intr_frame* f);
void sys_write(struct intr_frame* f);
void sys_seek(struct intr_frame* f);
void sys_tell(struct intr_frame* f);
void sys_close(struct intr_frame* f);
static void syscall_handler (struct intr_frame *);
struct open_file * find_file(int fd);


void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}
void * 
assert_is_vaddr(const void *vaddr,int offset)
{ 

  if (!is_user_vaddr(vaddr) || !pagedir_get_page (thread_current()->pagedir, vaddr)){
    thread_current()->child->status = -1;
    thread_exit ();
  }
  if (!is_user_vaddr(vaddr+offset) || !pagedir_get_page (thread_current()->pagedir, vaddr+offset)){
    thread_current()->child->status = -1;
    thread_exit ();
  }
}

static void
syscall_handler (struct intr_frame *f)
{
  int * p = f->esp;
  assert_is_vaddr (p+1, 3);
  int syscall_number = *(int *)f->esp;
  switch (*(int *)f->esp)
  {
  case SYS_HALT:
    sys_halt(f);
    break;
  case SYS_EXIT:
    sys_exit(f);
    break;
  case SYS_EXEC:
    sys_exec(f);
    break;
  case SYS_WAIT:
    sys_wait(f);
    break;
  case SYS_CREATE:
    sys_create(f);
    break;
  case SYS_REMOVE:
    sys_remove(f);
    break;
  case SYS_OPEN:
    sys_open(f);
    break;
  case SYS_WRITE:
    sys_write(f);
    break;
  case SYS_SEEK:
    sys_seek(f);
    break;
  case SYS_TELL:
    sys_tell(f);
    break;
  case SYS_CLOSE:
    sys_close(f);
    break;
  case SYS_READ:
    sys_read(f);
    break;
  case SYS_FILESIZE:
    sys_filesize(f);
    break;
  
  default:
    thread_current()->child->status = -1;
    thread_exit ();
    break;
  }

}
void 
sys_halt (struct intr_frame* f)
{
  shutdown_power_off();
}
void 
sys_exit (struct intr_frame* f)
{
  int *p = (int*)f->esp;
  assert_is_vaddr(p+1, 3);
  thread_current()->child->status = *(p+1);
  thread_exit();
}

void 
sys_exec (struct intr_frame* f)
{
  int *p = (int*)f->esp;
  assert_is_vaddr (p+1, 3);
  assert_is_vaddr(*(p+1), 3);
  f->eax = process_execute((char*)*(p+1));
}

void 
sys_wait (struct intr_frame* f)
{
  int *p = (int*)f->esp;
  assert_is_vaddr(p+1, 3);
  f->eax = process_wait(*(p+1));
}
//需要修改eax
void 
sys_create(struct intr_frame* f)
{
  int *p = (int*)f->esp;
  assert_is_vaddr(p+5, 3);
  assert_is_vaddr(*(p+4), 3);
  filesys_lock();
  f->eax = filesys_create((const char *)*(p+1), *(p+2));
  filesys_unlock();
}
void 
sys_remove(struct intr_frame* f)
{
  int *p = (int*)f->esp;
  assert_is_vaddr(p+1, 3);
  assert_is_vaddr(*(p+1), 3);
  filesys_lock();
  f->eax = filesys_remove((const char *)*(p+1));
  filesys_unlock();
}
//需要修改eax
void 
sys_open (struct intr_frame* f)
{
  int *p = (int*)f->esp;
  assert_is_vaddr (p+1, 3);
  assert_is_vaddr (*(p+1), 3);
  filesys_lock();
  struct file *file_opened = filesys_open((const char *)*(p+1));
  filesys_unlock();
  struct thread *t = thread_current();
  if (file_opened)
  {
    struct open_file *new_file = malloc(sizeof(struct open_file));
    new_file->fd = t->fd++;
    new_file->file = file_opened;
    list_push_back (&t->files, &new_file->file_elem);
    f->eax = new_file->fd;
  } 
  else
  {
    f->eax = -1;
  }
}
//需要修改eax
void 
sys_write (struct intr_frame* f)
{
  int *p = (int*)f->esp;
  assert_is_vaddr (p+7, 3);
  assert_is_vaddr (*(p+6), 3);
  int fd = *(p+1);
  char * buffer = (char *)*(p+2);
  int size = *(p+3);
  if (fd == STDOUT_FILENO) {
    putbuf(buffer,size);
    f->eax = size;
  }
  else
  {
    struct open_file * new_file = find_file (fd);
    if (new_file)
    {
      filesys_lock ();
      f->eax = file_write (new_file->file, buffer, size);
      filesys_unlock ();
    } 
    else
    {
      f->eax = 0;
    }
  }
}
void 
sys_seek(struct intr_frame* f)
{
  int *p = (int*)f->esp;
  assert_is_vaddr (p+5, 3);
  int fd = *(p+1);
  struct open_file *file_find = find_file (fd);
  if (file_find)
  {
    filesys_lock ();
    file_seek (file_find->file, *(p+2));
    filesys_unlock ();
  }
}
//需要修改eax
void 
sys_tell (struct intr_frame* f)
{
  int *p = (int*)f->esp;
  assert_is_vaddr (p+1, 3);
  int fd = *(p+1);
  struct open_file *file_find = find_file (fd);
  if (file_find)
  {
    filesys_lock ();
    f->eax = file_tell (file_find->file);
    filesys_unlock ();
  }
  else
  {
    f->eax = -1;
  }
}
void 
sys_close (struct intr_frame* f)
{
  int *p = (int*)f->esp;
  assert_is_vaddr (p+1, 3);
  int fd = *(p+1);
  struct open_file * file_open = find_file (fd);
  if (file_open)
  {
    filesys_lock ();
    file_close (file_open->file);
    filesys_unlock ();
    list_remove (&file_open->file_elem);
    free (file_open);
  }
}
//需要修改eax
void 
sys_filesize (struct intr_frame* f){
  int *p = (int*)f->esp;
  assert_is_vaddr(p+1, 3);
  int fd = *(p+1);
  struct open_file * file_find = find_file (fd);
  if (file_find)
  {
    filesys_lock ();
    f->eax = file_length (file_find->file);
    filesys_unlock ();
  } 
  else
  {
    f->eax = -1;
  }
}
//需要修改eax
void 
sys_read (struct intr_frame* f)
{
  int *p = (int*)f->esp;
  int fd = *(p+1);
  int i;
  uint8_t * buffer = (uint8_t*)*(p+2);
  off_t size = *(p+3);
  assert_is_vaddr (buffer, 0);
  assert_is_vaddr(buffer+size, 0);
  if (fd == STDIN_FILENO) 
  {
    for (i = 0; i < size; i++)
      buffer[i] = input_getc();
    f->eax = size;
  }
  else
  {
    struct open_file * file_find = find_file (fd);
    if (file_find)
    {
      filesys_lock ();
      f->eax = file_read (file_find->file, buffer, size);
      filesys_unlock ();
    } 
    else
    {
      f->eax = -1;
    }
  }
}

struct open_file * 
find_file (int file_id)
{
  struct list_elem *file_elem;
  struct open_file * file_find = NULL;
  struct list *files = &thread_current ()->files;
  for (file_elem = list_begin (files); file_elem != list_end (files); file_elem = list_next (file_elem)){
    file_find = list_entry (file_elem, struct open_file, file_elem);
    if (file_id == file_find->fd)
      return file_find;
  }
  return NULL;
}

