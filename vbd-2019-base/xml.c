 /**
 * section: Tree
 * synopsis: Navigates a tree to print element names
 * purpose: Parse a file to a tree, use xmlDocGetRootElement() to
 *          get the root element, then walk the document and print
 *          all the element name in document order.
 * usage: tree1 filename_or_URL
 * test: tree1 test2.xml > tree1.tmp && diff tree1.tmp $(srcdir)/tree1.res
 * author: Dodji Seketeli
 * copy: see Copyright for the status of this software.
 */
#include <stdio.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include <string.h>
#include "list.h"
#include "vcpu.h"

/*
 *To compile this file using gcc you can type
 *gcc `xml2-config --cflags --libs` -o xmlexample libxml2-example.c
 */

static void
get_node_REGISTER_children(xmlNode * a_node, TASK_STRUCT *task)
{
  xmlNode *cur_node = NULL;
  xmlChar *s = NULL;

  for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
    if (cur_node->type == XML_ELEMENT_NODE) {
      if ((!xmlStrcmp(cur_node->name, (const xmlChar *)"sp"))) {
	xmlChar *s = xmlNodeGetContent(cur_node);
	task->reg.__SP__ = strtoul(s, NULL, 16);
	xmlFree(s);
      }
      else if ((!xmlStrcmp(cur_node->name, (const xmlChar *)"lr"))) {
	xmlChar *s = xmlNodeGetContent(cur_node);
	task->reg.__LR__ = strtoul(s, NULL, 16);
	xmlFree(s);
      }
      else if ((!xmlStrcmp(cur_node->name, (const xmlChar *)"pc"))) {
	xmlChar *s = xmlNodeGetContent(cur_node);
	task->reg.__PC__ = strtoul(s, NULL, 16);
	xmlFree(s);
      }
      else if ((!xmlStrcmp(cur_node->name, (const xmlChar *)"cpsr"))) {
	xmlChar *s = xmlNodeGetContent(cur_node);
	unsigned int *p = (unsigned int *) &task->reg.cpsr;
	*p = strtoul(s, NULL, 16);
	xmlFree(s);
      }
    }
  }
}

static void
get_node_DEBUG_children(xmlNode * a_node, TASK_STRUCT *task)
{
  xmlNode *cur_node = NULL;
  xmlChar *s = NULL;

  for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
    if (cur_node->type == XML_ELEMENT_NODE) {
      if ((!xmlStrcmp(cur_node->name, (const xmlChar *)"breakpoint"))) {
	xmlChar *s = xmlNodeGetContent(cur_node);
	task->break_point = strtoul(s, NULL, 16);
	xmlFree(s);
      }
      else if ((!xmlStrcmp(cur_node->name, (const xmlChar *)"watchpoint"))) {
	xmlChar *s = xmlNodeGetContent(cur_node);
	task->watch_point = strtoul(s, NULL, 16);
	xmlFree(s);
      }
      else if ((!xmlStrcmp(cur_node->name, (const xmlChar *)"watchsize"))) {
	xmlChar *s = xmlNodeGetContent(cur_node);
	task->watch_size = atoi(s);
	xmlFree(s);
      }
    }
  }
}

static void
get_node_TASK_children(xmlNode * a_node, TASK_STRUCT *task)
{
  xmlNode *cur_node = NULL;
  xmlChar *s = NULL;

  for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
    if (cur_node->type == XML_ELEMENT_NODE) {
      if ((!xmlStrcmp(cur_node->name, (const xmlChar *)"register"))) {
	get_node_REGISTER_children(cur_node->children, task);
      }
      else if ((!xmlStrcmp(cur_node->name, (const xmlChar *)"debug"))) {
	get_node_DEBUG_children(cur_node->children, task);
      }
      else if ((!xmlStrcmp(cur_node->name, (const xmlChar *)"exefile"))) {
	xmlChar *s = xmlNodeGetContent(cur_node);
	strcpy(task->comm, s);
	xmlFree(s);
      }
      else if ((!xmlStrcmp(cur_node->name, (const xmlChar *)"cpumask"))) {
	xmlChar *s = xmlNodeGetContent(cur_node);
	task->cpu_mask = strtoul(s, NULL, 16);
	xmlFree(s);
      }
      else if ((!xmlStrcmp(cur_node->name, (const xmlChar *)"weight"))) {
	xmlChar *s = xmlNodeGetContent(cur_node);
	task->nice = atoi(s);
	xmlFree(s);
      }
      else if ((!xmlStrcmp(cur_node->name, (const xmlChar *)"pid"))) {
	xmlChar *s = xmlNodeGetContent(cur_node);
	task->pid = atoi(s);
	xmlFree(s);
      }
    }
  }
}

static void
get_node_TASKSET_children(xmlNode * a_node, struct list_head *task_list)
{
  xmlNode *cur_node = NULL;
  xmlChar *s = NULL;
  TASK_STRUCT *task;

  for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
    if (cur_node->type == XML_ELEMENT_NODE) {
      if ((!xmlStrcmp(cur_node->name, (const xmlChar *)"task"))) {
	if ((task = (TASK_STRUCT *) malloc(sizeof(TASK_STRUCT))) == NULL)
	  quit("malloc");

	get_node_TASK_children(cur_node->children, task);

	INIT_LIST_HEAD(&task->task_list);
	list_add(&task->task_list, task_list);
      }
    }
  }
}

static void
get_node_SYSTEM_children(xmlNode * a_node, VBD_CONFIG *vbd_config)
{
  xmlNode *cur_node = NULL;
  xmlChar *s = NULL;

  for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
    if (cur_node->type == XML_ELEMENT_NODE) {
      if ((!xmlStrcmp(cur_node->name, (const xmlChar *)"vmemfile"))) {
	xmlChar *s = xmlNodeGetContent(cur_node);
	strcpy(vbd_config->vmem_file, s);
	xmlFree(s);
      }
      else if ((!xmlStrcmp(cur_node->name, (const xmlChar *)"vmempages"))) {
	xmlChar *s = xmlNodeGetContent(cur_node);
	vbd_config->vmem_pages = atoi(s);
	xmlFree(s);
      }
      else if ((!xmlStrcmp(cur_node->name, (const xmlChar *)"schedpolicy"))) {
	xmlChar *s = xmlNodeGetContent(cur_node);
	strcpy(vbd_config->sched_policy, s);
	xmlFree(s);
      }
      else if ((!xmlStrcmp(cur_node->name, (const xmlChar *)"timeslice"))) {
	xmlChar *s = xmlNodeGetContent(cur_node);
	vbd_config->timeslice = atoi(s);
	xmlFree(s);
      }
      else if ((!xmlStrcmp(cur_node->name, (const xmlChar *)"timelimit"))) {
	xmlChar *s = xmlNodeGetContent(cur_node);
	vbd_config->timelimit = atoi(s);
	xmlFree(s);
      }
    }
  }
}

static void
get_node_VBD_children(xmlNode * a_node, VBD_CONFIG *vbd_config)
{
  xmlNode *cur_node = NULL;

  for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
    if (cur_node->type == XML_ELEMENT_NODE) {
      if ((!xmlStrcmp(cur_node->name, (const xmlChar *)"system"))) {
	get_node_SYSTEM_children(cur_node->children, vbd_config);
      }
      else if ((!xmlStrcmp(cur_node->name, (const xmlChar *)"taskset"))) {
	get_node_TASKSET_children(cur_node->children, &vbd_config->task_list);
      }
    }
  }
}

static void
get_node_VBD(xmlNode * a_node, VBD_CONFIG *vbd_config)
{
  xmlNode *cur_node = NULL;

  for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
    if (cur_node->type == XML_ELEMENT_NODE) {
      if ((!xmlStrcmp(cur_node->name, (const xmlChar *)"vbd"))) {
	get_node_VBD_children(cur_node->children, vbd_config);
      }
    }
  }
}

int read_vbd_config(char *xml_file, VBD_CONFIG *vbd_config) {
  xmlDoc *doc = NULL;
  xmlNode *root_element = NULL;

  /*
   * this initialize the library and check potential ABI mismatches
   * between the version it was compiled for and the actual shared
   * library used.
   */
  LIBXML_TEST_VERSION

  /* parse the file and get the DOM */
  doc = xmlReadFile(xml_file, NULL, 0);

  if (doc == NULL) {
    printf("error: could not parse file %s\n", xml_file);
    return -1;
  }

  /* get the root element node */
  root_element = xmlDocGetRootElement(doc);

  /* parse all the element nodes */
  get_node_VBD(root_element, vbd_config);

  /* free the document */
  xmlFreeDoc(doc);

  /*
   * Free the global variables that may
   * have been allocated by the parser.
   */
  xmlCleanupParser();
  return 0;
}
