/*
 * lttng-ftrace.c
 *
 * LTTng function graph
 *
 * Copyright (C) 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#include <linux/module.h>
#include <linux/ftrace.h>
#include <linux/printk.h>
#include <wrapper/kallsyms.h>
#include <wrapper/ftrace.h>
#include <wrapper/tracepoint.h>
#include <wrapper/vmalloc.h>
#include <lttng-tracer.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/preempt.h>

#include "lttng-fgraph.h"

#define TP_MODULE_NOAUTOLOAD
#define LTTNG_PACKAGE_BUILD
#define CREATE_TRACE_POINTS
#define TRACE_INCLUDE_PATH instrumentation/events/lttng-module
#define TRACE_INCLUDE_FILE fgraph
#define LTTNG_INSTRUMENTATION

#include <instrumentation/events/lttng-module/fgraph.h>

DEFINE_TRACE(func_entry);
DEFINE_TRACE(func_exit);
DEFINE_TRACE(func_entry_exit);

static int (*register_ftrace_graph_sym)(trace_func_graph_ret_t retfunc,
			trace_func_graph_ent_t entryfunc);
static void (*unregister_ftrace_graph_sym)(void);

static unsigned int max_depth = 10;
static unsigned int exit_only = 0;
static atomic_t entries = ATOMIC_INIT(0);
static atomic_t returns = ATOMIC_INIT(0);

static inline long string_hash(char* string, int length)
{
    int len = length;
    unsigned char *p;
    long x; /* Notice the 64-bit hash, at least on a 64-bit system */

    p = (unsigned char *) string;
    x = *p << 7;
    while (--len >= 0){
        x = (1000003*x) ^ *p++;
    }
    x ^= length;
    if (x == -1)
        x = -2;
    return x;
}
static long get_hash_code(unsigned long address)
{
    char name[KSYM_SYMBOL_LEN];
    sprint_symbol_no_offset(name, address);
    return string_hash(name, strlen(name));
}
// called by prepare_ftrace_return()
// The corresponding return hook is called only when this function returns 1
int notrace lttng_fgraph_entry(struct ftrace_graph_ent *trace)
{
	int ret = 0;
	int bit;
	unsigned long hash_code = 0;

	// For now, only trace normal context
	if (in_interrupt())
		return 0;

	if((trace->depth < 0) || (max_depth && trace->depth >= max_depth))
        return 0;

	// check recursion
	preempt_disable_notrace();
	bit = trace_test_and_set_recursion(TRACE_FTRACE_START, TRACE_FTRACE_MAX);

	if (bit < 0)
		goto out;

	if (!exit_only)
	{
		// record event
		hash_code = get_hash_code(trace->func);
		trace_func_entry(trace->func, hash_code, trace->depth);
	}
	trace_clear_recursion(bit);
	atomic_inc(&entries);
	ret = 1;
out:
	preempt_enable_notrace();
	return ret;
}

// called by ftrace_return_to_handler()
void notrace lttng_fgraph_return(struct ftrace_graph_ret *trace)
{
	int bit;

	preempt_disable_notrace();
	bit = trace_test_and_set_recursion(TRACE_FTRACE_START, TRACE_FTRACE_MAX);

	if (bit < 0)
		goto out;

	// record event
	if (exit_only) {
		trace_func_entry_exit(trace->func, get_hash_code(trace->func),
			trace->depth, trace->calltime);
	}
	else {
		trace_func_exit(trace->func, trace->depth, trace->rettime - trace->calltime);
	}
	trace_clear_recursion(bit);
	atomic_inc(&returns);
out:
	preempt_enable_notrace();
	return;
}

static int __init lttng_fgraph_init(void)
{
	int ret;
	(void) wrapper_lttng_fixup_sig(THIS_MODULE);

	register_ftrace_graph_sym = (void *) kallsyms_lookup_funcptr("register_ftrace_graph");
	unregister_ftrace_graph_sym = (void *) kallsyms_lookup_funcptr("unregister_ftrace_graph");

	printk("register=%p unregister=%p\n", register_ftrace_graph_sym,
			unregister_ftrace_graph_sym);

	if (!register_ftrace_graph_sym ||
	    !unregister_ftrace_graph_sym) {
		printk("lttng-fgraph init failed\n");
		return -1;
	}

	ret = register_ftrace_graph_sym(lttng_fgraph_return, lttng_fgraph_entry);
	if (ret) {
		printk("register fgraph hooks failed ret=%d\n", ret);
		return -1;
	}

	ret = __lttng_events_init__fgraph();
	if (ret)
		return -1;

	printk("lttng-fgraph loaded\n");
	return 0;
}
module_init(lttng_fgraph_init);

static void __exit lttng_fgraph_exit(void)
{
	unregister_ftrace_graph_sym();
	synchronize_rcu();
	__lttng_events_exit__fgraph();
	printk("lttng-fgraph removed\n");
	printk("entries=%d returns=%d\n", atomic_read(&entries),
			atomic_read(&returns));
}
module_exit(lttng_fgraph_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau <francis.giraldeau@gmail.com>");
MODULE_DESCRIPTION("LTTng function graph");
MODULE_VERSION(__stringify(LTTNG_MODULES_MAJOR_VERSION) "."
	__stringify(LTTNG_MODULES_MINOR_VERSION) "."
	__stringify(LTTNG_MODULES_PATCHLEVEL_VERSION)
	LTTNG_MODULES_EXTRAVERSION);
