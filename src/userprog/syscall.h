#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

#define REMOVE -1
#define ERR -1

#define N_LOAD 0
#define S_LOAD 1
#define F_LOAD 2

struct child_process
{
  int pid;
  int load_pid;
  int wait_pid;
  int exit_pid;
  int stat_pid;
  struct lock wait;
  struct list_elem l_pid;
};

struct p_file
{
  struct file* file;
  int fd;
  struct list_elem el;
};

void syscall_init (void);
//static void syscall_handler(struct intr_frame*);

void halt(void);
void exit(int status);
//pid_t exec(const char* cmd_line);
//int wait(pid_t pid);
bool create(const char* file, unsigned initial_size);
bool remove(const char* file);
int open(const char* file);
int filesize(int fd);
int read(int fd, void* buffer, unsigned size);
int write(int fd, const void* buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

struct child_process* add_cp(int pid);
void rm_cp(struct child_process* cp);
void rm_cp_mult(void);

int user_to_kernel(const void *vaddr);
//void get_arg(struct intr_frame* f, int* args, int n);
void check_ptr(const void* vaddr);
void check_buffer(void* buffer, unsigned sz);
struct child_process* get_cp(int pid);
int add_file(struct file* file);
struct file* get_file(int fd);
void close_file(int fd);

#endif /* userprog/syscall.h */
