/*
 *  dlinklist.c
 *  Router
 *
 *  Created by Alex Heinz on 4/24/10.
 *
 */

#include "dlinklist.h"
#include <stdlib.h>
#include <assert.h>

dlinklist* dlinklist_init()
{
	dlinklist* newList = calloc(1, sizeof(dlinklist));
	
	return newList;
}

void dlinklist_destroy(dlinklist* list)
{
	if (list == NULL)
		return;
	
	// Iterate through each node in the list
	dlinklist_node* node = list->head;
	dlinklist_node* temp_next;
	while (node != NULL)
	{
		// Hold a reference to the next node
		temp_next = node->next;
		
		// Free the node's contents
		free(node->contents);
		
		// Free the node itself
		free(node);
		
		// Move to the next node in the list
		node = temp_next;
	}
	
	// Free the list struct
	free(list);
}

dlinklist_node* dlinklist_add(dlinklist* list, void* node_contents)
{
	assert(list != NULL);
	
	// Create a new node, wrapping the provided contents
	dlinklist_node* newNode = calloc(1, sizeof(dlinklist_node));
	if (newNode == NULL)
		return NULL;
	
	// Insert the contents of node
	newNode->contents = node_contents;
	
	// Add the node to the list
	dlinklist_addnode(list, newNode);
	
	return newNode;
}

void dlinklist_addnode(dlinklist* list, dlinklist_node* node)
{
	assert(list != NULL);
	assert(node != NULL);
	
	// If the list is empty, set the node as head and tail of the list
	if (list->count == 0)
	{
		list->head = node;
		list->tail = node;
	}
	// If the list is non-empty, add the node to the end
	else
	{
		list->tail->next = node;
		node->prev = list->tail;
		list->tail = node;
	}
	
	// Increment count of nodes
	list->count++;
}

dlinklist_node* dlinklist_find(dlinklist* list, const void* const compare_value, bool (*compare)(const void* const, const void* const))
{
	assert(list != NULL);
	assert(compare != NULL);
	
	// Iterate over the list
	dlinklist_node* node = list->head;
	while (node != NULL)
	{
		// Check if this node's contents are equal to the contents to find when compared
		if (compare(node->contents, compare_value))
			return node;
		
		node = node->next;
	}
	
	return NULL;
}

void dlinklist_removenode(dlinklist* list, dlinklist_node* node)
{
	assert(list != NULL);
	assert(node != NULL);
	
	// "Cross wire" the node's neighbors in the list
	if (list->head == node)
		list->head = node->next;
	else
		node->prev->next = node->next;
	
	if (list->tail == node)
		list->tail = node->prev;
	else
		node->next->prev = node->prev;
	
	// Free the node
	free(node->contents);
	free(node);
	
	// Decrement count of nodes in the list
	list->count--;
}
