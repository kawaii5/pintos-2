#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h" 
#include "userprog/pagedir.h"
#include "userprog/process.h"

#define BOTTOM ((void*) 0x08048000)

struct lock file_lock;

static void syscall_handler(struct intr_frame*);

pid_t exec(const char* cmd_line);
int wait(pid_t pid);
void get_arg(struct intr_frame* f, int* args, int n);


void
syscall_init (void) 
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int args[3];
  check_ptr((const void*) f->esp);
  switch(*(int*) f->esp)
  {
    case SYS_HALT:
    {
      halt();
      break;
    }
    case SYS_EXIT:
    {
      get_arg(f, &args[0], 1);
      exit(args[0]);
      break;
    }
    case SYS_EXEC:
    {
      get_arg(f, &args[0], 1);
      args[0] = user_to_kernel((const void*) args[0]);
      f->eax = exec((const char*) args[0]);
      break;
    }
    case SYS_WAIT:
    {
      get_arg(f, &args[0], 1);
      f->eax = wait(args[0]);
      break;
    }
    case SYS_CREATE:
    {
      get_arg(f, &args[0], 2);
      args[0] = user_to_kernel((const void*) args[0]);
      f->eax = create((const char*) args[0], (unsigned) args[1]);
      break;
    }
    case SYS_REMOVE:
    {
      get_arg(f, &args[0], 1);
      args[0] = user_to_kernel((const void*) args[0]);
      f->eax = remove((const char*) args[0]);
      break;
    }
    case SYS_OPEN:
    {
      get_arg(f, &args[0],1);
      args[0] = user_to_kernel((const void *) args[0]);
      f->eax = open((const char*) args[0]);
      break;
    }
    case SYS_FILESIZE:
    {
      get_arg(f, &args[0], 1);
      f->eax = filesize(args[0]);
      break;
    }
    case SYS_READ:
    {
      get_arg(f, &args[0], 3);
      check_buffer((void*) args[1], (unsigned) args[2]);
      args[1] = user_to_kernel((const void*) args[1]);
      f->eax = read(args[0], (void*) args[1], (unsigned) args[2]);
      break;
    }
    case SYS_WRITE:
    {
      get_arg(f, &args[0], 3);
      check_buffer((void*) args[1], (unsigned) args[2]);
      args[1] = user_to_kernel((const void*) args[1]);
      f->eax = write(args[0], (const void*) args[1], (unsigned) args[2]);
      break;

    }
    case SYS_SEEK:
    {
      get_arg(f, &args[0], 2);
      seek(args[0], (unsigned) args[0]);
      break;
    }
    case SYS_TELL:
    { 
      get_arg(f, &args[0], 1);
      f->eax = tell(args[0]);
      break;
    }
    case SYS_CLOSE:
    { 
      get_arg(f, &args[0], 1);
      close(args[0]);
      break;
    }
  }
}

void 
halt(void)
{
  shutdown_power_off();
}

void 
exit(int status)
{
  struct thread *cur = thread_current();
  if (living_thread(cur->par))
    cur->cp->stat_pid = status;
  printf ("%s: exit(%d)\n", cur->name, status);
  thread_exit();
}

pid_t 
exec(const char *cmd_line)
{
  pid_t pid = process_execute(cmd_line);
  struct child_process* cp = get_cp(pid);
  ASSERT(cp);
  while (cp->load_pid == N_LOAD)
    barrier();
  if (cp->load_pid == F_LOAD)
    return -1;
  return pid;
}

int wait(pid_t pid)
{
  return process_wait(pid);
}

bool 
create (const char *file, unsigned initial_size)
{
  lock_acquire(&file_lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&file_lock);
  return success;
}

bool 
remove (const char *file)
{
  lock_acquire(&file_lock);
  bool success = filesys_remove(file);
  lock_release(&file_lock);
  return success;
}

int 
open (const char *file)
{
  lock_acquire(&file_lock);
  struct file *f = filesys_open(file);
  if (!f)
  {
    lock_release(&file_lock);
    return -1;
  }
  int fd = add_file(f);
  lock_release(&file_lock);
  return fd;
}

int 
filesize (int fd)
{
  lock_acquire(&file_lock);
  struct file *f = get_file(fd);
  if (!f)
  {
    lock_release(&file_lock);
    return -1;
  }
  int size = file_length(f);
  lock_release(&file_lock);
  return size;
}

int 
read (int fd, void *buffer, unsigned size)
{
  if (fd == STDIN_FILENO)
  {
    unsigned i;
    uint8_t* local_buffer = (uint8_t *) buffer;
    for (i = 0; i < size; i++)
      local_buffer[i] = input_getc();
    return size;
  }
  lock_acquire(&file_lock);
  struct file *f = get_file(fd);
  if (!f)
  {
    lock_release(&file_lock);
    return -1;
  }
  int bytes = file_read(f, buffer, size);
  lock_release(&file_lock);
  return bytes;
}

int 
write (int fd, const void *buffer, unsigned size)
{
  if (fd == STDIN_FILENO)
    return -1;
  if (fd == STDOUT_FILENO)
  {
    putbuf(buffer, size);
    return size;
  }
  lock_acquire(&file_lock);
  struct file *f = get_file(fd);
  int bytes = -1;
  /*if (!f)
  {
    lock_release(&file_lock);
    return -1;
  }
  int bytes = file_write(f, buffer, size);*/
  if(f)
    bytes = file_write(f, buffer, size);
  lock_release(&file_lock);
  return bytes;
}

void 
seek (int fd, unsigned position)
{
  lock_acquire(&file_lock);
  struct file *f = get_file(fd);
  if (!f)
  {
    lock_release(&file_lock);
    return;
  }
  file_seek(f, position);
  lock_release(&file_lock);
}

unsigned 
tell (int fd)
{
  lock_acquire(&file_lock);
  struct file *f = get_file(fd);
  if (!f)
  {
    lock_release(&file_lock);
    return -1;
  }
  off_t offset = file_tell(f);
  lock_release(&file_lock);
  return offset;
}

void 
close (int fd)
{
  lock_acquire(&file_lock);
  close_file(fd);
  lock_release(&file_lock);
}


struct child_process* 
add_cp (int pid)
{
  struct child_process* cp = malloc(sizeof(struct child_process));
  cp->pid = pid;
  cp->load_pid = N_LOAD;
  cp->wait_pid = false;
  cp->exit_pid = false;
  lock_init(&cp->wait);
  list_push_back(&thread_current()->c_list,
     &cp->l_pid);
  return cp;
}

void 
rm_cp (struct child_process *cp)
{
  list_remove(&cp->l_pid);
  free(cp);
}

void 
rm_cp_mult (void)
{
  struct thread *t = thread_current();
  struct list_elem *next, *e = list_begin(&t->c_list);

  while (e != list_end (&t->c_list))
    {
      next = list_next(e);
      struct child_process *cp = list_entry (e, struct child_process,
               l_pid);
      list_remove(&cp->l_pid);
      free(cp);
      e = next;
    }
}

int 
user_to_kernel(const void *vaddr)
{
  check_ptr(vaddr);
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if (!ptr)
    exit(-1);
  return (int) ptr;
}

void 
get_arg(struct intr_frame *f, int *args, int n)
{
  int i;
  int *ptr;
  for (i = 0; i < n; i++)
  {
    ptr = (int *) f->esp + i + 1;
    check_ptr((const void *) ptr);
    args[i] = *ptr;
  }
}

void 
check_ptr (const void *vaddr)
{
  if (!is_user_vaddr(vaddr) || vaddr < BOTTOM)
    exit(-1);
}

void 
check_buffer(void* buffer, unsigned size)
{
  unsigned i;
  char* local_buffer = (char *) buffer;
  for (i = 0; i < size; i++)
    check_ptr((const void*) local_buffer++);
}

struct child_process* 
get_cp (int pid)
{
  struct thread *t = thread_current();
  struct list_elem *e;

  for (e = list_begin (&t->c_list); e != list_end (&t->c_list);
       e = list_next (e))
  {
    struct child_process *cp = list_entry (e, struct child_process, l_pid);
    if (pid == cp->pid)
      return cp;
  }
  return NULL;
}

int 
add_file (struct file *f)
{
  struct p_file *pf = malloc(sizeof(struct p_file));
  pf->file = f;
  pf->fd = thread_current()->fd;
  thread_current()->fd++;
  list_push_back(&thread_current()->f_list, &pf->el);
  return pf->fd;
}

struct file* 
get_file (int fd)
{
  struct thread *t = thread_current();
  struct list_elem *e;

  for (e = list_begin (&t->f_list); e != list_end (&t->f_list);
       e = list_next (e))
  {
    struct p_file *pf = list_entry (e, struct p_file, el);
    if (fd == pf->fd)
      return pf->file;
  }
  return NULL;
}

void 
close_file (int fd)
{
  struct thread *t = thread_current();
  struct list_elem *next, *e = list_begin(&t->f_list);

  while (e != list_end (&t->f_list))
  {
    next = list_next(e);
    struct p_file *pf = list_entry (e, struct p_file, el);
    if (fd == pf->fd || fd == -1)
    {
      file_close(pf->file);
      list_remove(&pf->el);
      free(pf);
      if (fd != -1)
        return;
    }
    e = next;
  }
}
