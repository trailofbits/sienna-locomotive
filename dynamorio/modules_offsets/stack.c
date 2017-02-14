#include "stack.h"

#pragma once

struct stack_element *tail = NULL;

// I can't figure out where this dumbass function is in Windows
char *strdup(const char *s) {
	char *d = malloc(strlen(s) + 1);
	if (d == NULL) return NULL;
	strcpy(d, s);
	return d;
}

int push(struct stack_element *elem) {
	elem->prev = tail;
	tail = elem;
	return 0;
}

struct stack_element *peek() {
	return tail;
}

struct stack_element *pop() {
	struct stack_element* ret = tail;
	if (ret != NULL) {
		tail = ret->prev;
	}
	return ret;
}

int push_alloc(char *module, app_pc offset) {
	struct stack_element *elem = NULL;
	elem = malloc(sizeof(struct stack_element));

	if (elem == NULL)
		return 1;

	elem->prev = tail;
	elem->offset = offset;
	elem->module = strdup(module);
	
	tail = elem;

	return 0;
}

int pop_free() {
	if (tail != NULL) {
		struct stack_element *elem = tail;
		tail = elem->prev;
		if (elem->module != NULL) {
			free(elem->module);
		}
		free(elem);
	} else {
		return 1;
	}

	return 0;
}