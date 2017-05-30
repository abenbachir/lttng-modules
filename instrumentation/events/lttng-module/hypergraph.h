#undef TRACE_SYSTEM
#define TRACE_SYSTEM hypergraph

#if !defined(_HYPERGRAPH_H) || defined(TRACE_HEADER_MULTI_READ)
#define _HYPERGRAPH_H

#include <probes/lttng-tracepoint-event.h>
#include <linux/tracepoint.h>

LTTNG_TRACEPOINT_EVENT(hypergraph_host,
	TP_PROTO(unsigned long nr, unsigned long a0, unsigned long a1, 
		unsigned long a2, unsigned long a3, unsigned int vcpu_id, 
		unsigned long guest_rip, unsigned long overhead),
	TP_ARGS(nr, a0, a1, a2, a3, vcpu_id, guest_rip, overhead),
	TP_FIELDS(
		ctf_integer(unsigned long, nr, nr)
		ctf_integer(unsigned long, a0, a0)
		ctf_integer(unsigned long, a1, a1)
		ctf_integer(unsigned long, a2, a2)
		ctf_integer(unsigned long, a3, a3)
		ctf_integer(unsigned int, vcpu_id, vcpu_id)
		ctf_integer(unsigned long, guest_rip, guest_rip)
		ctf_integer(unsigned long, overhead, overhead)
	)
)

#endif /* _HYPERGRAPH_H */

/* This part must be outside protection */
#include <probes/define_trace.h>