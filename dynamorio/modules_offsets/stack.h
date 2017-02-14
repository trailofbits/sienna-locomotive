#pragma once
#include <stddef.h>
#include <malloc.h>
#include "dr_api.h"

struct stack_element {
	char *module;
	app_pc offset;
	struct stack_element *prev;
};

struct stack_element* tail;

int push(struct stack_element*);
struct stack_element *pop();
struct stack_element *peek();

int push_alloc(char *module, app_pc offset);
int pop_free();