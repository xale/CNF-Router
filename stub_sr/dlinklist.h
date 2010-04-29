/*
 *  dlinklist.h
 *  Router
 *
 *  Created by Alex Heinz on 4/24/10.
 *
 */

#ifndef _DLINKLIST_H
#define _DLINKLIST_H

#include <stdbool.h>

typedef struct dlinklist_node
{
	void* contents;
	struct dlinklist_node* prev;
	struct dlinklist_node* next;
} dlinklist_node;

typedef struct dlinklist
{
	dlinklist_node* head;
	dlinklist_node* tail;
	unsigned long count;
} dlinklist;

// Creates and returns a new doubly-linked list (or NULL if malloc fails)
dlinklist* dlinklist_init();

// Frees a doubly-linked list and any nodes in the list (contents of the nodes are also freed)
void dlinklist_destroy(dlinklist*);

// Creates and adds to the list a new node with the specified contents; returns a pointer to the new node if the operation succeeds, NULL if malloc fails
dlinklist_node* dlinklist_add(dlinklist* list, void* node_contents);

// Adds the specified node to the end of the list
void dlinklist_addnode(dlinklist* list, dlinklist_node* node);

// Finds the node in the list that returns true when compared to the specified value using the specified comparator, or NULL if no such node exists
dlinklist_node* dlinklist_find(dlinklist* list, const void* const compare_value, bool (*compare)(const void* const list_entry, const void* const compare_value));

// Removes the specified node from the list
void dlinklist_removenode(dlinklist* list, dlinklist_node* node);

#endif // _DLINKLIST_H
