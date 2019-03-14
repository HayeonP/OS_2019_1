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

#include "elf.h"
#include "vcpu.h"

static void get_elf_header(unsigned long long *mmap_addr, ARM_EXEC_HDR *arm_exec_h) {
  int ph_ent, sh_ent;

  // ELF header
  arm_exec_h->e_h = malloc(sizeof(ELF_HDR));
  if (arm_exec_h->e_h == NULL) quit("malloc");
  memcpy(arm_exec_h->e_h, mmap_addr, sizeof(ELF_HDR));
    
  // Program headers
  ph_ent = arm_exec_h->e_h->e_phnum;
  arm_exec_h->p_h = malloc(sizeof(ELF_PROG_HDR) * ph_ent);
  if (arm_exec_h->p_h == NULL) quit("malloc");
  memcpy(arm_exec_h->p_h, (unsigned int*) mmap_addr + arm_exec_h->e_h->e_phoff/4, sizeof(ELF_PROG_HDR)*ph_ent);

  // Section headers
  sh_ent = arm_exec_h->e_h->e_shnum;
  arm_exec_h->s_h = (ELF_SECT_HDR*) malloc(sizeof(ELF_SECT_HDR) * sh_ent);
  if (arm_exec_h->s_h == NULL) quit("malloc");
  memcpy(arm_exec_h->s_h, (unsigned int*) mmap_addr + arm_exec_h->e_h->e_shoff/4, sizeof(ELF_SECT_HDR)*sh_ent);
}

static void free_elf_header(ARM_EXEC_HDR *arm_exec_h) {
    free(arm_exec_h->e_h);
    free(arm_exec_h->p_h);
    free(arm_exec_h->s_h);
}

static void print_prog_headers(ELF_PROG_HDR *prog_hdr, int nhdrs) {
  int i;

  printf("\n\nProgram Headers:\n  Type\t\tOffset\t\tVirtAddr\tPhysAddr\tFilesiz\tMemSiz\tFlg\tAlign\n");

  for (i = 0; i < nhdrs; i++) {
    char type[20];
    char flag[10];
        
    switch(prog_hdr[i].p_type) {
    case 0x1: strcpy(type,"LOAD"); break;
    case 0x4: strcpy(type,"NOTE"); break;
    case 0x7: strcpy(type,"TLS"); break;
    case 0x70000001: strcpy(type,"EXIDX"); break;
    default :strcpy(type,"GNU_STACK"); break;
    }
        
    switch(prog_hdr[i].p_flags & 0b111) {
    case 0b001: strcpy(flag,"  E");break;
    case 0b010: strcpy(flag," W ");break;
    case 0b100: strcpy(flag,"R  ");break;
    case 0b011: strcpy(flag," WE");break;
    case 0b101: strcpy(flag,"R E");break;
    case 0b110: strcpy(flag,"RW ");break;
    case 0b111: strcpy(flag,"RWE");break;
    default : strcpy(flag,"   ");break;
    }

    printf("  %-8s\t0x%06x\t0x%08x\t0x%08x\t0x%05x\t0x%05x\t%s\t0x%x\n",
	   type, prog_hdr[i].p_offset, 
	   prog_hdr[i].p_vaddr, 
	   prog_hdr[i].p_paddr,
	   prog_hdr[i].p_filesz, 
	   prog_hdr[i].p_memsz, 
	   flag, prog_hdr[i].p_align);
  }
}

static void print_sect_headers(ELF_SECT_HDR *sect_hdr, int nhdrs) {
  unsigned int symtab_base;
  char type[10];
  char flag[10];
  char name[20];
  int i = 0;

  printf("\nSection Headers:\n");
  printf("[Nr]  Name\t\ttype\t\tAddr\t\tOff\t\t  Size\t\tES    Flg Lk Inf Al\n");

  while (1) {
    if(sect_hdr[i].sh_type == 0x02) {
      symtab_base = sect_hdr[i].sh_offset;
      i = 0;
      break;
    }
    i++;
  }
    
  for(i = 0; i < nhdrs; i++) {
    switch(sect_hdr[i].sh_type) {
    case 0x00: strcpy(type,"NULL"); break;
    case 0x07: strcpy(type,"NOTE"); break;
    case 0x01: strcpy(type,"PROGBITS"); break;
    case 0x70000001: strcpy(type,"ARM_EXIDX"); break;
    case 0x08: strcpy(type,"NOBITS"); break;
    case 0x0e: strcpy(type,"INIT_ARRAY"); break;
    case 0x0f: strcpy(type,"FINI_ARRAY"); break;
    case 0x70000003: strcpy(type,"ARM_ATTRIBUTE"); break;
    case 0x03: strcpy(type,"STRTAB"); break;
    case 0x02: strcpy(type,"SYMTAB"); break;
    }

    switch(sect_hdr[i].sh_flags) {
    case 0x2: strcpy(flag,"A"); break;
    case 0x6: strcpy(flag,"AX"); break;
    case 0x82: strcpy(flag,"AL"); break;
    case 0x403: strcpy(flag,"WAT"); break;
    case 0x3: strcpy(flag,"WA"); break;
    case 0x30: strcpy(flag,"MS"); break;
    case 0x00: strcpy(flag,"   "); break;
    }
    
    printf("[%2d]  %-10x%-10s\t0x%08x  0x%06x  0x%06x  0x%02x  %3s  %d  %d  %d\n", 
	   i, sect_hdr[i].sh_name, 
	   type, sect_hdr[i].sh_addr, 
	   sect_hdr[i].sh_offset,
	   sect_hdr[i].sh_size, 
	   sect_hdr[i].sh_entsize, 
	   flag, sect_hdr[i].sh_link,
	   sect_hdr[i].sh_info, 
	   sect_hdr[i].sh_addralign);
  }
}

// print all headers info (same as readelf)
void print_elf_header(ARM_EXEC_HDR *arm_exec_h) {
  int i, ph_ent, sh_ent;
    
  printf("ELF HEADER:\n");
  printf("\tMagic:\t");

  for(i = 0; i < EI_INDENT; i++)
    printf("%02x ", arm_exec_h->e_h->e_indent[i]);

  printf("\n\tEntry Point address : \t\t0x%x", arm_exec_h->e_h->e_entry);
  printf("\n\tStart of program headers : \t%d (0x%x) bytes into file", 
	 arm_exec_h->e_h->e_phoff, arm_exec_h->e_h->e_phoff);
  printf("\n\tStart of section headers : \t%d (0x%x) bytes into file",
	 arm_exec_h->e_h->e_shoff, arm_exec_h->e_h->e_shoff);
  printf("\n\tSize of this header: \t\t%d (bytes)", arm_exec_h->e_h->e_ehsize);
  printf("\n\tNumber of program headers : \t%d", arm_exec_h->e_h->e_phnum);
  printf("\n\tSize of program header : \t%d (bytes)", arm_exec_h->e_h->e_phentsize);
  printf("\n\tNumber of section headers : \t%d", arm_exec_h->e_h->e_shnum);
  printf("\n\tSize of section header : \t%d (bytes)", arm_exec_h->e_h->e_shentsize);

  print_prog_headers(arm_exec_h->p_h, arm_exec_h->e_h->e_phnum);
  print_sect_headers(arm_exec_h->s_h, arm_exec_h->e_h->e_shnum);        
}

void read_elf(unsigned long long *elf_base_addr, MM_STRUCT *mm) {
  ARM_EXEC_HDR  arm_exec_h;
  int i, ph_ent;
  unsigned int start_of_text;

  get_elf_header(elf_base_addr, &arm_exec_h);
  if (glob_debug)
    print_elf_header(&arm_exec_h);

  // bugfix by khkim on 20180519:  e_phentsize was replaced to e_phnum!
  ph_ent = arm_exec_h.e_h->e_phnum;
  for (i = 0; i < ph_ent; i++) {
    switch(arm_exec_h.p_h[i].p_type) {
    case 0x1: 
      if (arm_exec_h.p_h[i].p_flags & 0b010) {
	mm->data_vaddr = arm_exec_h.p_h[i].p_vaddr;
	mm->data_offset = arm_exec_h.p_h[i].p_offset;
	mm->data_size = arm_exec_h.p_h[i].p_memsz;
	break;
      } 
      else {
	start_of_text= arm_exec_h.p_h[i].p_vaddr;
	mm->text_vaddr = arm_exec_h.p_h[i].p_vaddr;
	mm->text_offset = arm_exec_h.p_h[i].p_offset;
	mm->text_size = arm_exec_h.p_h[i].p_memsz;
	break;
      }
    default: break;
    }
  }
  free_elf_header(&arm_exec_h);
}
