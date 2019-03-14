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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "vcpu.h"

#define FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

void *vmem_base;
struct page *mem_map;
struct list_head free_page_list_head;
struct list_head *free_page_list;
struct list_head active_page_list_head;
struct list_head *active_page_list;

void free_page(struct page *p) {
  //INIT_LIST_HEAD(&p->page_list);
  list_add(&p->page_list, free_page_list);
}

struct page *__alloc_page() {
  struct page *p = list_entry(free_page_list->next, typeof(*p), page_list);
  list_del_init(&p->page_list);
  list_add(&p->page_list, active_page_list);
  memset(__guest_to_host_addr(p->virtual), 0, PAGE_SIZE);
  return p;
}

unsigned long alloc_page() {
  struct page *p = __alloc_page();
  return p->virtual;
}

void print_page_list(int flag) {
  int i = 0;
  struct page *p, *n;

  if (flag == 0) {
    list_for_each_entry_safe(p, n, free_page_list, page_list) {
      if (p) {
	printf("free_page_list[%d]: virtual = 0x%lx, virtual64 = %p\n", 
	       i++, p->virtual, __guest_to_host_addr(p->virtual));
      }
    }
  }
  else if (flag == 1) {
    list_for_each_entry_safe(p, n, active_page_list, page_list) {
      if (p) {
	printf("active_page_list[%d]: virtual = 0x%lx, virtual64 = %p\n", 
	       i++, p->virtual, __guest_to_host_addr(p->virtual));
      }
    }
  }
}

void init_vmem(char *vmem_file, int pages) {
  int i, fd, size = pages * PAGE_SIZE;
  void *vmem;

  if ((fd = open(vmem_file, O_RDWR | O_CREAT | O_TRUNC, FILE_MODE)) < 0)
    quit("open error");

  if (ftruncate(fd, size) < 0)
    quit("ftruncate error");

  if ((vmem_base = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED)
    quit("mmap error for vmem");

  if ((mem_map = (struct page *) malloc(sizeof(struct page)*pages)) == NULL)
    quit("malloc error");

  free_page_list = &free_page_list_head;
  INIT_LIST_HEAD(free_page_list);
  for (i = 0; i < pages; i++) {
    mem_map[i].virtual = PAGE_OFFSET + i*0x1000;
    free_page(&mem_map[i]);
  }

  active_page_list = &active_page_list_head;
  INIT_LIST_HEAD(active_page_list);
  //alloc_page();  alloc_page();   // debugging purposes

  print_page_list(0);
}
