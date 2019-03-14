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

#ifndef __VCPU_H__
#define __VCPU_H__

#include "list.h"

#define MAX_STRING 128
#define NR_CORES 4  // should be a power of 2

///////////////////////////////////////////////////////////////////////////
// Definitions of Instruction types
///////////////////////////////////////////////////////////////////////////

typedef struct arm_inst_DPR_format { // format for arm data-processing instructions
  unsigned short Rm         :4;
  unsigned short subcode :4;
  unsigned short Rx          :4;
  unsigned short Rd          :4;
  unsigned short Rn          :4;
  unsigned short Sbit        :1;
  unsigned short opcode   :4;
  unsigned short type       :3;
  unsigned short cond      :4;
} ARM_INST_DPR;

typedef struct arm_inst_DPI_format { // format for arm data-processing instructions with immediates
  unsigned short operand2 :12;
  unsigned short Rd           :4;
  unsigned short Rn           :4;
  unsigned short Sbit         :1;
  unsigned short opcode    :4;
  unsigned short type        :3;
  unsigned short cond       :4;
} ARM_INST_DPI;

typedef  ARM_INST_DPI  ARM_INST_COMMON;

typedef struct arm_inst_SDI_format { // format for arm single-data-transfer instructions with immediates
  unsigned short imm12 :12;
  unsigned short Rt        :4;
  unsigned short Rn       :4;
  unsigned short Lbit      :1;
  unsigned short Wbit    :1;
  unsigned short Bbit     :1;
  unsigned short Ubit     :1;
  unsigned short Pbit     :1;
  unsigned short type   :3;
  unsigned short cond   :4;
} ARM_INST_SDI;

typedef struct arm_inst_BDT_format { // format for arm block-data-transfer instructions
    unsigned int regs      :16;
    unsigned int Rn        :4;
    unsigned int opcode :5;
    unsigned int type     :3;
    unsigned int cond    :4;
} ARM_INST_BDT;

typedef struct arm_inst_BRN_format { // format for arm branch instructions
    unsigned int imm24 :24;
    unsigned int Lbit    :1;
    unsigned int type   :3;
    unsigned int cond  :4;
} ARM_INST_BRN;

typedef struct arm_inst_BXW_format { // format for arm BXWritePC instructions
    unsigned int Rm         :4;
    unsigned int constant :24;
    unsigned int cond       :4;
} ARM_INST_BXW;

#define TRAP_INST_CODE  0xffffffff

///////////////////////////////////////////////////////////////////////////
// Definition of ARM CORE
///////////////////////////////////////////////////////////////////////////
typedef struct cpsr {
    unsigned int mode :5;
    unsigned int t      :1;
    unsigned int f      :1;
    unsigned int i      :1;
    unsigned int _f1 :16;
    unsigned int j      :1;
    unsigned int _f2  :2;
    unsigned int Q    :1;
    unsigned int V    :1;
    unsigned int C    :1;
    unsigned int Z    :1;
    unsigned int N    :1;
} CPSR;

typedef struct arm_reg {
#define __FP__  regs[11]
#define __SP__  regs[13]
#define __LR__  regs[14]
#define __PC__  regs[15]
  unsigned int regs[16];    // ARM registers
  CPSR  cpsr;                    // CPSR register
  unsigned int branch_taken; // is the branch taken in the previous instruction?
  unsigned int curr_inst;    // current instruction
  unsigned int inst_count; // number of instructions executed
} ARM_REG;

typedef struct mm_struct MM_STRUCT;
typedef struct arm_core {
  ARM_REG reg;
  MM_STRUCT *mm;
} ARM_CORE;


///////////////////////////////////////////////////////////////////////////
// Definition of Linux-specific data structures
///////////////////////////////////////////////////////////////////////////
#define PAGE_SHIFT  (12)
#define PAGE_SIZE  (1 << PAGE_SHIFT)
#define PAGE_MASK  (~(PAGE_SIZE-1))
#define PAGE_OFFS(v)  ((v) & ((PAGE_SIZE)-1))
#define PAGE_DOWN(v)  ((v) & PAGE_MASK)
#define PAGE_ADDR(v)  ((void *) PAGE_DOWN(v))

// defined in include/linux/page-flags.h
struct page {
  unsigned long virtual;
  struct list_head page_list;
};

// defined in arch/arm/include/asm/pgtable.h
#define PAGE_OFFSET  (0xC0000000)
#define PGDIR_SHIFT  (22)
#define PTRS_PER_PTE  (1024)
#define pgd_index(addr)  ((addr) >> PGDIR_SHIFT)
#define pgd_offset(mm, addr)  ((mm)->pgd + (pgd_index(addr) << 2))
#define pgd_present(x)  (x)
#define pte_index(addr)  (((addr) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1))
#define pte_offset(pte, addr)  ((pte) + (pte_index(addr) << 2))
#define pte_present(x)  (x)

extern void *vmem_base;  // main memory emulation
static void *__guest_to_host_addr(unsigned int addr)
{
  void *p = vmem_base + addr - PAGE_OFFSET;
  return p;
}

// vm_flags defined in include/linux/mm.h
#define VM_NONE		0x00000000
#define VM_READ		0x00000001
#define VM_WRITE		0x00000002
#define VM_EXEC		0x00000004
#define VM_SHARED	0x00000008

#define MEM_READ  0
#define MEM_WRITE  1
#define MEM_PEEK  2  // does not cause any memory access violation

typedef struct mm_struct {
  char exe_file[MAX_STRING];
  struct list_head vm_area_list;
  unsigned int pgd;
  unsigned char *text_base;  // base address of the text segment
  unsigned char *data_base;  // base address of the data segment
  unsigned char *stack_base; // base address of the stack segment
  unsigned int text_vaddr;
  unsigned int text_offset;
  unsigned int text_size;
  unsigned int data_vaddr;
  unsigned int data_offset;
  unsigned int data_size;
  unsigned int stack_iaddr;
  unsigned int stack_size;
} MM_STRUCT;

typedef struct vm_area_struct {
  unsigned long vm_start;
  unsigned long vm_end;
  unsigned long vm_flags;
  unsigned long vm_pgoff;
  int vm_fd; // struct file *vm_file;
  MM_STRUCT *vm_mm;
  struct list_head vm_area_list;
} VM_AREA_STRUCT;

#if 0
#include "rbtree.h"
#define u64 unsigned long long
#define s64 signed long long
#define MIG 131072
#define sched_min_granularity 750 // us
#endif
#define MAX_TASKS 100

typedef struct task_struct {
  char comm[MAX_STRING];
  ARM_REG reg;
  MM_STRUCT mm;
  unsigned int break_point;
  unsigned int inst_at_bp;
  unsigned int watch_point;
  unsigned int watch_size;
  unsigned int cpu_mask;
  unsigned int nice;
  unsigned int pid;
  struct list_head task_list;
} TASK_STRUCT;

typedef struct vbd_config {
  // SYSTEM node
  char vmem_file[MAX_STRING];
  unsigned int vmem_pages;
  char sched_policy[MAX_STRING];
  unsigned int timeslice;
  unsigned int timelimit;
  // TASKSET node
  struct list_head task_list;
} VBD_CONFIG;


///////////////////////////////////////////////////////////////////////////
// Declarations of extern variables and functions
///////////////////////////////////////////////////////////////////////////
extern ARM_CORE vcpu[NR_CORES];
extern TASK_STRUCT *current[NR_CORES];
extern int glob_verbose;
extern int glob_debug;
extern int glob_interactive;
extern VBD_CONFIG config;
extern struct list_head *glob_active_task_list;
extern struct list_head *glob_zombie_task_list;
extern int glob_timer_interrupts_generated;
extern int glob_timer_interrupts_handled;

extern int timer_interrupt_handler(void);
extern void load_program(MM_STRUCT *mm, char *exe_file);
extern void init_core(ARM_CORE *core);
extern void switch_out(ARM_CORE *core, TASK_STRUCT *out);
extern void switch_in(ARM_CORE *core, TASK_STRUCT *in);
extern int run_core(ARM_CORE *core);
extern void print_regs(ARM_REG *reg);
extern TASK_STRUCT *remove_task(struct list_head *task_list);

extern void free_page(struct page *p);
extern struct page *__alloc_page();
extern unsigned long alloc_page();
extern void print_page_list(int flag);
extern void init_vmem(char *vmem_file, int pages);

///////////////////////////////////////////////////////////////////////////
// Program-specific macros
///////////////////////////////////////////////////////////////////////////
#define PROG_INITIAL_LR  0x88888888
#define PROG_INITIAL_SP  0x80000000
#define PROG_STACK_SIZE 0x00100000
#define PROG_STACK_BASE (PROG_INITIAL_SP - PROG_STACK_SIZE)

#endif // __VCPU_H__
