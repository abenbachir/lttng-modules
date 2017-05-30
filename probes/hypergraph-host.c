/*
 *
 * hypergraph host module : Hook to kvm probe entry exit and hypercall
 *
 * Copyright (C) 2017 Abderrahmane Benbachir <abderrahmane.benbachir@polymtl.ca>
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
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/kallsyms.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/preempt.h>
#include <linux/tracepoint.h>
#include <linux/slab.h>
#include <linux/kvm_host.h>
#include <../arch/x86/kvm/kvm_cache_regs.h>


#include "../wrapper/tracepoint.h"
#include "../wrapper/kallsyms.h"
#include "../lttng-abi.h"
#define TP_MODULE_NOAUTOLOAD
#define LTTNG_PACKAGE_BUILD
#define CREATE_TRACE_POINTS
#define LTTNG_INSTRUMENTATION
#define TRACE_INCLUDE_PATH instrumentation/events/lttng-module
#define TRACE_INCLUDE_FILE hypergraph


#include <instrumentation/events/lttng-module/hypergraph.h>

DEFINE_TRACE(hypergraph_host);

#define HYPERCALL_EXIT_REASON 18
#define GET_CLOCK_MONOTONIC() ktime_to_ns(ktime_get())

struct tracepoint_entry {
	void *probe;
	const char *name;
	struct tracepoint *tp;	
};

struct kvm_node {
	int start;
	/* kvm_exit */
	unsigned int exit_reason;
	unsigned long guest_rip;
	unsigned int isa;
	unsigned long kvm_exit_timestamp;
	/* kvm_hypercall */
	unsigned long nr;
	unsigned long a0;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;	
	/* kvm_entry */
	unsigned int vcpu_id;	
	unsigned long kvm_entry_timestamp;
};
static struct kvm_node kvm_nodes_list[NR_CPUS];

static int hypergraph_tracepoint_notify(struct notifier_block *self, unsigned long val, void *data);
static void kvm_exit_handler(void *__data, unsigned int exit_reason, struct kvm_vcpu *vcpu, u32 isa);
static void kvm_hypercall_handler(void *__data, unsigned long nr,
		unsigned long a0, unsigned long a1, unsigned long a2, unsigned long a3);
static void kvm_entry_handler(void *__data, unsigned int vcpu_id);

static struct notifier_block hypergraph_tracepoint_notifier = {
	.notifier_call = hypergraph_tracepoint_notify,
	.priority = 0,
};
static struct tracepoint_entry tracepoint_table[] = {
	{ .name = "kvm_entry", 		.probe = kvm_entry_handler },
	{ .name = "kvm_exit", 		.probe = kvm_exit_handler },
	{ .name = "kvm_hypercall", 	.probe = kvm_hypercall_handler }
};
static size_t TABLE_SIZE = sizeof(tracepoint_table) / sizeof(tracepoint_table[0]);

static 
void print_kvm_node(struct kvm_node *node)
{
	printk("kvm_node: nr=%lu, a0=%lu, a1=%lu, a2=%lu, a3=%lu", node->nr, node->a0, node->a1, node->a2, node->a3);
	printk("\texit_timestamp=%lu, exit_reason=%u, guest_rip=%lu, isa=%u",node->kvm_exit_timestamp, node->exit_reason, node->guest_rip, node->isa);
	printk("\tentry_timestamp=%lu, vcpu_id=%d",node->kvm_entry_timestamp, node->vcpu_id);
	printk("\toverhead=%lu",node->kvm_entry_timestamp-node->kvm_exit_timestamp);
}

static
void kvm_exit_handler(void *__data, unsigned int exit_reason, struct kvm_vcpu *vcpu, u32 isa)
{
	int cpu;
	if (exit_reason != HYPERCALL_EXIT_REASON)
		return;

	cpu = smp_processor_id();
	kvm_nodes_list[cpu].start = 1;
	kvm_nodes_list[cpu].exit_reason = exit_reason;
	kvm_nodes_list[cpu].guest_rip = kvm_rip_read(vcpu);
	// kvm_nodes_list[cpu].isa = isa;
	kvm_nodes_list[cpu].kvm_exit_timestamp = GET_CLOCK_MONOTONIC();
	// printk("kvm_exit exit_reason=%u, guest_rip=%lu, isa=%u\n", exit_reason, guest_rip, isa);
}

static
void kvm_hypercall_handler(void *__data, unsigned long nr,
		unsigned long a0, unsigned long a1, unsigned long a2, unsigned long a3)
{
	int cpu = smp_processor_id();
	if(kvm_nodes_list[cpu].start <= 0)
		return;

	kvm_nodes_list[cpu].nr = nr;
	kvm_nodes_list[cpu].a0 = a0;
	kvm_nodes_list[cpu].a1 = a1;
	kvm_nodes_list[cpu].a2 = a2;
	kvm_nodes_list[cpu].a3 = a3;
	// printk("kvm_hypercall nr=%lu, a0=%lu, a1=%lu, a2=%lu, a3=%lu\n", nr, a0, a1, a2, a3);
}

static
void kvm_entry_handler(void *__data, unsigned int vcpu_id)
{	
	int cpu = smp_processor_id();
	if(kvm_nodes_list[cpu].start <= 0)
		return;

	kvm_nodes_list[cpu].start = 0;
	kvm_nodes_list[cpu].vcpu_id = vcpu_id;
	kvm_nodes_list[cpu].kvm_entry_timestamp = GET_CLOCK_MONOTONIC();
	// print_kvm_node(&kvm_nodes_list[cpu]);

	/* Trace the event */
	long overhead = kvm_nodes_list[cpu].kvm_entry_timestamp - kvm_nodes_list[cpu].kvm_exit_timestamp;
	trace_hypergraph_host(kvm_nodes_list[cpu].nr, kvm_nodes_list[cpu].a0,
		kvm_nodes_list[cpu].a1, kvm_nodes_list[cpu].a2,
		kvm_nodes_list[cpu].a3, kvm_nodes_list[cpu].vcpu_id,
		kvm_nodes_list[cpu].guest_rip, overhead);
	
}

static int hypergraph_tracepoint_probe_register(struct tracepoint_entry *entry)
{
	int ret = 0;

	if(entry->tp == NULL){
		printk("register %s hooks failed, tracepoint not found\n", entry->name);
		return -EINVAL;
	}

	ret = tracepoint_probe_register(entry->tp, entry->probe, NULL);
	if(ret){
		printk("register %s hooks failed ret=%d\n", entry->name, ret);
		tracepoint_probe_unregister(entry->tp, entry->probe, NULL);
		return ret;
	}

	printk("tracepoint found: %p %s\n", entry->tp, entry->tp ? entry->tp->name : "null");
	return ret;
}

static void hypergraph_tracepoint_probe_unregister(struct tracepoint_entry *entry)
{
	if(entry == NULL)
		return;
	if(entry->tp == NULL || entry->probe == NULL)
		return;

	printk("%s probe was unregistered\n", entry->name);
	tracepoint_probe_unregister(entry->tp, entry->probe, NULL);
}

static
int hypergraph_tracepoint_coming(struct tp_module *tp_mod)
{
	int i, j, ret = 0;

	for (i = 0; i < tp_mod->mod->num_tracepoints; i++) {
		struct tracepoint *tp;
		tp = tp_mod->mod->tracepoints_ptrs[i];	
		
		// register probes if they match
		for(j = 0; j < TABLE_SIZE; j++) {
			if (strcmp(tp->name, tracepoint_table[j].name) == 0) {
				tracepoint_table[j].tp = tp;
				ret = hypergraph_tracepoint_probe_register(&tracepoint_table[j]);
			}
		}		
	}
	return ret;
}

static
int hypergraph_tracepoint_notify(struct notifier_block *self,
		unsigned long val, void *data)
{
	struct tp_module *tp_mod = data;
	int ret = 0;

	switch (val) {
		case MODULE_STATE_COMING:
			ret = hypergraph_tracepoint_coming(tp_mod);
			break;
		case MODULE_STATE_GOING:
			// ...
			break;
		default:
			break;
	}
	return ret;
}


static int __init hypergraph_init(void)
{
	int ret;

	ret = __lttng_events_init__hypergraph();

	ret = register_tracepoint_module_notifier(&hypergraph_tracepoint_notifier);
	if(ret)
		return ret;

	printk("hypergraph-host module loaded\n");
	return ret;
}
module_init(hypergraph_init);

static void __exit hypergraph_exit(void)
{
	int i;
	for(i = 0; i < TABLE_SIZE; i++)
		hypergraph_tracepoint_probe_unregister(&tracepoint_table[i]);

	// synchronize_rcu();
	unregister_tracepoint_module_notifier(&hypergraph_tracepoint_notifier);
	
	printk("hypergraph-host module removed\n");
}
module_exit(hypergraph_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Abderrahmane Benbachir <abderrahmane.benbachir@polymtl.ca>");
MODULE_DESCRIPTION("Hypergraph host handler");
MODULE_VERSION("1.0");
