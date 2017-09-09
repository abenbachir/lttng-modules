#undef TRACE_SYSTEM
#define TRACE_SYSTEM fgraph

#if !defined(LTTNG_TRACE_FGRAPH_H) || defined(TRACE_HEADER_MULTI_READ)
#define LTTNG_TRACE_FGRAPH_H

#include <probes/lttng-tracepoint-event.h>

LTTNG_TRACEPOINT_EVENT(func_entry,
	TP_PROTO(unsigned long ip, unsigned long long hash, unsigned int depth),
	TP_ARGS(ip, hash, depth),
	TP_FIELDS(
		ctf_integer_hex(unsigned long, ip, ip)
		ctf_integer(unsigned long long, hash, hash)
		ctf_integer(unsigned int, depth, depth)
	)
)

// FIXME: func_exit has no payload. How can we define a tracepoint
// without argument? TP_PROTO() and TP_PROTO(void) failed to compile
LTTNG_TRACEPOINT_EVENT(func_exit,
	TP_PROTO(unsigned long ip, unsigned int depth, unsigned long duration),
	TP_ARGS(ip, depth, duration),
	TP_FIELDS(
		ctf_integer_hex(unsigned long, ip, ip)
		ctf_integer(unsigned int, depth, depth)
		ctf_integer(unsigned int, duration, duration)
	)
)

LTTNG_TRACEPOINT_EVENT(func_entry_exit,
	TP_PROTO(unsigned long ip, unsigned long long hash, unsigned int depth, unsigned long long calltime),
	TP_ARGS(ip, hash, depth, calltime),
	TP_FIELDS(
		ctf_integer_hex(unsigned long, ip, ip)
		ctf_integer(unsigned long, hash, hash)
		ctf_integer(unsigned int, depth, depth)
		ctf_integer(unsigned long long, calltime, calltime)
	)
)


#endif /* LTTNG_TRACE_FGRAPH_H */

/* This part must be outside protection */
#include <probes/define_trace.h>
