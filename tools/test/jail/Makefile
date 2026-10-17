PROG=	jail_get_bench
MAN=

PYTHON?=	python3
DTRACE?=	dtrace
DTRACEFLAGS?=	-x nolibs

.if make(smoke)
MAX_JAILS?=	10
LIST_EVERY?=	1
.else
MAX_JAILS?=	10000
LIST_EVERY?=	100
.endif
REPEATS?=	5
WARMUPS?=	1
MODES?=		jid,default
OUTPUT?=
PAUSE_AT?=
ALLOW_EXISTING?=	no
RUN?=
INPUT?=		.
KEEP_JAILS?=	no
CLEANUP_ORDER?=	reverse
DRAIN_TIMEOUT?=	30

TRACE_REPEATS?=	20
TRACE_LABEL?=	manual
TRACE_DIR?=	${.OBJDIR}/traces

_RUNNER=	${.CURDIR}/jailbench.py
_SYSCALL_TRACE=	${.CURDIR}/jls.d
_LOCK_TRACE=	${.CURDIR}/allprison_wait.d
_PROBE=		${.OBJDIR}/${PROG}
_BENCH_ARGS=	--max-jails ${MAX_JAILS:Q} --list-every ${LIST_EVERY:Q} \
		--repeats ${REPEATS:Q} --warmups ${WARMUPS:Q} \
		--modes ${MODES:Q} --probe ${_PROBE:Q} \
		--cleanup-order ${CLEANUP_ORDER:Q} --drain-timeout ${DRAIN_TIMEOUT:Q}
.if !empty(OUTPUT)
_BENCH_ARGS+=	--output ${OUTPUT:Q}
.endif
.if !empty(PAUSE_AT)
_BENCH_ARGS+=	--pause-at ${PAUSE_AT:Q}
.endif
.if ${ALLOW_EXISTING:tl} == "yes"
_BENCH_ARGS+=	--allow-existing
.endif

.if ${KEEP_JAILS:tl} == "yes"
_BENCH_ARGS+=	--keep-jails
.endif

_CLEANUP_ARGS=	--cleanup-order ${CLEANUP_ORDER:Q} --drain-timeout ${DRAIN_TIMEOUT:Q}
_ENUM_COMMAND=	./${PROG} enum ${TRACE_REPEATS}
_TRACE_JLS=	${TRACE_DIR}/jls-${TRACE_LABEL}.txt
_TRACE_ENUM=	${TRACE_DIR}/enum-${TRACE_LABEL}.txt
_TRACE_LOCK=	${TRACE_DIR}/lock-${TRACE_LABEL}.txt
_TRACE_CLEANUP=	${TRACE_DIR}/cleanup-${TRACE_LABEL}.txt

.PHONY: test benchmark smoke cleanup-run report trace trace-jls trace-enum trace-lock trace-cleanup

test benchmark smoke: ${PROG}
	${PYTHON:Q} ${_RUNNER:Q} ${_BENCH_ARGS}

report:
	${PYTHON:Q} ${.CURDIR:Q}/report.py ${INPUT:Q}

cleanup-run:
.if empty(RUN)
	@echo "Set RUN to a saved run directory" >&2
	@false
.else
	${PYTHON:Q} ${_RUNNER:Q} --cleanup-run ${RUN:Q} ${_CLEANUP_ARGS}
.endif

# Destructive: trace exactly one cleanup of a retained benchmark population.
trace-cleanup:
.if empty(RUN)
	@echo "Set RUN to a retained benchmark run directory" >&2
	@false
.else
	${PYTHON:Q} ${_RUNNER:Q} --cleanup-run ${RUN:Q} ${_CLEANUP_ARGS} \
	    --trace-cleanup ${_TRACE_CLEANUP:Q} --dtrace ${DTRACE:Q} \
	    --dtrace-flags=${DTRACEFLAGS:Q}
.endif

# Run separately from timing trials, while the population is paused.
# Recursive makes keep these tracing passes sequential even with make -j.
trace:
	${MAKE} -C ${.CURDIR:Q} trace-jls
	${MAKE} -C ${.CURDIR:Q} trace-enum
	${MAKE} -C ${.CURDIR:Q} trace-lock

trace-jls:
	mkdir -p ${TRACE_DIR:Q}
	${DTRACE:Q} ${DTRACEFLAGS} -q -o ${_TRACE_JLS:Q} -s ${_SYSCALL_TRACE:Q} \
	    -c '/usr/sbin/jls -n jid' > /dev/null
	@echo "DTrace report:" ${_TRACE_JLS:Q}

trace-enum: ${PROG}
	mkdir -p ${TRACE_DIR:Q}
	${DTRACE:Q} ${DTRACEFLAGS} -q -o ${_TRACE_ENUM:Q} -s ${_SYSCALL_TRACE:Q} \
	    -c ${_ENUM_COMMAND:Q} > /dev/null
	@echo "DTrace report:" ${_TRACE_ENUM:Q}

trace-lock: ${PROG}
	mkdir -p ${TRACE_DIR:Q}
	${DTRACE:Q} ${DTRACEFLAGS} -q -o ${_TRACE_LOCK:Q} -s ${_LOCK_TRACE:Q} \
	    -c ${_ENUM_COMMAND:Q} > /dev/null
	@echo "DTrace report:" ${_TRACE_LOCK:Q}

.include <bsd.prog.mk>
