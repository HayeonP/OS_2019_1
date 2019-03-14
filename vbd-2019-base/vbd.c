/*
 * Copyright (c) 2018   Soongsil University
 *
 * Authors: Doosol Lee, Hyoeun Lee, Kyujin Choi, and Kanghee Kim
 *               at Rubicom Lab (http://rubicom.ssu.ac.kr)
 *
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, 
 *     this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *     this list of conditions and the following disclaimer in the documentation and/or 
 *     other materials provided with the distribution. 
 * 3. Neither the name of the copyright holder nor the names of its contributors 
 *     may be used to endorse or promote products derived from this software without 
 *     specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR 
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; 
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF 
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>
#include <sys/timerfd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>

#include "list.h"
#include "vcpu.h"

int glob_verbose = 1;
int glob_debug = 0;
int glob_interactive = 0;
char glob_config_file[MAX_STRING];

VBD_CONFIG config;
struct list_head zombie_task_list;
struct list_head *glob_active_task_list;
struct list_head *glob_zombie_task_list;
int glob_return_value;
int glob_timer_interrupts_generated;
int glob_timer_interrupts_handled;

pthread_barrier_t *vcpus_start_barrier;
pthread_barrier_t *vcpus_end_barrier;

#if 0
struct sched_system glob_sched_sys;
u64 glob_round_length;
int glob_err;
double glob_avg_load;
double glob_threshold;
double glob_load_threshold;
int glob_rounds_cnt[MIG] = {0,};
#endif
int glob_nr_tasks;
TASK_STRUCT *glob_tasks[MAX_TASKS];

///////////////////////////////////////////////////////////////////////////
// Linux dependent code
///////////////////////////////////////////////////////////////////////////
static struct termios oldterm, newterm;

/* Initialize new terminal i/o settings */
static void init_termios(int echo) {
  tcgetattr(0, &oldterm); /* grab old terminal i/o settings */
  newterm = oldterm; /* make new settings same as old settings */
  newterm.c_lflag &= ~ICANON; /* disable buffered i/o */
  newterm.c_lflag &= echo ? ECHO : ~ECHO; /* set echo mode */
  tcsetattr(0, TCSANOW, &newterm); /* use these new terminal i/o settings now */
}

/* Restore old terminal i/o settings */
static void reset_termios(void) {
  tcsetattr(0, TCSANOW, &oldterm);
}

/* Read 1 character - echo defines echo mode */
static char getch_(int echo) {
  char ch;
  init_termios(echo);
  ch = getchar();
  reset_termios();
  return ch;
}

/* Read 1 character without echo */
char getch(void) {  return getch_(0); }

/* Read 1 character with echo */
char getche(void) {  return getch_(1); }

int init_timer(int msec) {
  int ret;
  int fd = -1;
  struct itimerspec timeout;
  unsigned long long missed;

  if (msec >= 1000) {
    printf("init_timer() accepts 1~999 ms.\n");
    exit(1);
  }

  if ((fd = timerfd_create(CLOCK_REALTIME, 0)) <= 0)
    quit("timerfd_create");

  //if ((ret = fcntl(fd, F_SETFL, O_NONBLOCK)) != 0)
  //  quit("fcntl");

  timeout.it_value.tv_sec = 0;
  timeout.it_value.tv_nsec = msec * 1000 * 1000;
  timeout.it_interval.tv_sec = 0; /* recurring */
  timeout.it_interval.tv_nsec = msec * 1000 * 1000;
  if ((ret = timerfd_settime(fd, 0, &timeout, NULL)) != 0)
    quit("timerfd_settime");

  return fd;
}

///////////////////////////////////////////////////////////////////////////
// TASK management code
///////////////////////////////////////////////////////////////////////////
void print_tasks(struct list_head *task_list) {
  TASK_STRUCT *p, *n;
  list_for_each_entry_safe(p, n, task_list, task_list) {
    if (p) {
      printf("[PID=%d, INST=%d]\n", p->pid, p->reg.inst_count);
      printf("ARM executable file = %s\n", p->comm);
      printf("break_point = 0x%08x\n", p->break_point);
      printf("watch_point = 0x%08x\n", p->watch_point);
      printf("watch_size = %d\n", p->watch_size);
      printf("cpu_mask = 0x%08x\n", p->cpu_mask);
      print_regs(&p->reg);
    }
  }
}

void load_tasks(struct list_head *task_list) {
  TASK_STRUCT *p, *n;
  list_for_each_entry_safe(p, n, task_list, task_list) {
    if (p) {
      p->reg.branch_taken = 1; // necessary to initialize to 1
      load_program(&p->mm, p->comm);
      
      glob_tasks[glob_nr_tasks++] = p; // initialize glob_tasks array

      if (p->break_point > 0)
	set_breakpoint(p);
    }
  }
}

void add_task(TASK_STRUCT *p, struct list_head *task_list) {
  list_add_tail(&p->task_list, task_list);
}

TASK_STRUCT *remove_task(struct list_head *task_list) {
  TASK_STRUCT *p = list_first_entry(task_list, typeof(*p), task_list);
  list_del_init(&p->task_list);
  return p;
}

void *run_tasks(void *arg) {
  ARM_CORE *core = arg;

  pthread_barrier_wait(vcpus_start_barrier);
  printf("vcpu_start_barrier\n");

  if (core == &vcpu[0]) {
  TASK_STRUCT *p = remove_task(glob_active_task_list);
  switch_in(core, p);

  // The following code should not be modified.
  run_core(core);
  glob_return_value = core->reg.inst_count;
  }
  else
    glob_return_value = -1;

  pthread_barrier_wait(vcpus_end_barrier);
  printf("vcpu_end_barrier\n");
  return &glob_return_value;
}

void switch_task(void) {
  // TODO
}

int timer_interrupt_handler(void) {
  // TODO 
}

///////////////////////////////////////////////////////////////////////////
// Main code
///////////////////////////////////////////////////////////////////////////

void usage(char *progname) {
  printf("usage: %s [-d] [-i] [-c config_file] \n", progname);
}

int main(int argc,char *argv[]) {
  ARM_CORE *core = &vcpu[0];
  TASK_STRUCT *task;
  pthread_t tid;
  int i, timerfd, inst_count, n_intr;
  void *ret;
  unsigned long long missed;
  int opt;

  while ((opt = getopt(argc, argv, "c:di")) != -1) {
    switch (opt) {
    case 'c': strcpy(glob_config_file, optarg); break;
    case 'd': glob_debug = 1; break;
    case 'i': glob_interactive = 1; break;
    default:
      printf("unexpected options!\n");
      usage(argv[0]);
      exit(1);
    }
  }

  if (optind > argc) { 
    printf("unknown arguments\n");
    usage(argv[0]);
    exit(1);
  }
 
  if (strlen(glob_config_file) == 0) {
    printf("No config file given\n");
    usage(argv[0]);
    exit(1);
  }

  // task list initalization phase
  glob_active_task_list = &config.task_list;
  glob_zombie_task_list = &zombie_task_list;
  INIT_LIST_HEAD(glob_active_task_list);
  INIT_LIST_HEAD(glob_zombie_task_list);

  // configuration reading phase
  read_vbd_config(glob_config_file, &config);
  printf("vmem_file = %s\n", config.vmem_file);
  printf("vmem_pages = %d\n", config.vmem_pages);
  printf("sched_policy = %s\n", config.sched_policy);
  printf("timeslice = %d\n", config.timeslice);
  printf("timelimit = %d\n", config.timelimit);

  // vmem initialization phase:
  // vmem should be initialized before load_program() is called
  // because it requires to allocate a page directory.
  init_vmem(config.vmem_file, config.vmem_pages);

  // tasks loading phase
  print_tasks(glob_active_task_list);
  load_tasks(glob_active_task_list);

#if 0
  glob_round_length = sched_min_granularity * glob_nr_tasks / NR_CORES;
  set_cpu_info(&glob_sched_sys);
  set_task_info(&glob_sched_sys);

  int rounds = 1000;
  for(i = 1; i <= rounds; i++) { 
    update_cpu_node(&glob_sched_sys, i);
    printf("---------------------------round(%d)----------------------------\n", i);
    print_cpu(&glob_sched_sys, 0);
    delay_bound_lb(&glob_sched_sys, i);
  }

  print_system(&glob_sched_sys, rounds);
#endif


  // system timer initialization
  timerfd = init_timer(config.timeslice);

  // vcpu initialization phase: run_tasks(core)
  vcpus_start_barrier = (pthread_barrier_t *) malloc(sizeof(pthread_barrier_t));
  vcpus_end_barrier = (pthread_barrier_t *) malloc(sizeof(pthread_barrier_t));
  pthread_barrier_init(vcpus_start_barrier, NULL, NR_CORES);
  pthread_barrier_init(vcpus_end_barrier, NULL, NR_CORES);
  for (i = 0; i < NR_CORES; i++) {
    init_core(&core[i]);
    if (pthread_create(&tid, NULL, run_tasks, &core[i]) < 0)
      quit("pthread_create");
    pthread_detach(tid);
  }

  n_intr = config.timelimit/config.timeslice;
  for (i = 0; i < n_intr; i++) {
    while (read(timerfd, &missed, sizeof(missed)) < 0)
      printf("error: no timer expiry!!!\n");
    glob_timer_interrupts_generated++;
    printf("timer interrupt generated (%d, %d)...\n",   //"(%lld)\n", missed);
	   glob_timer_interrupts_generated, glob_timer_interrupts_handled); 
    fflush(stdout);
  }
  close(timerfd);

  // result summary phase
  inst_count = *((int *) ret);
  print_tasks(glob_zombie_task_list);
  printf("inst_count = %d\n", inst_count);
  print_page_list(1);
  fflush(stdout);

  return 0;
}
