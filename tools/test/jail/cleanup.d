#!/usr/sbin/dtrace -s
/* Run via make trace-cleanup; the runner specializes this prefix per run. */
#pragma D option quiet

inline string bench_prefix = "jidbench_";

/* The target is the cleanup runner; jail/jls are its direct children. */
syscall::jail_get:entry,
syscall::jail_remove:entry
/pid == $target || ppid == $target/
{
	@sys_entries[execname, probefunc] = count();
	self->sys_wall = timestamp;
	self->sys_cpu = vtimestamp;
}

syscall::jail_get:return,
syscall::jail_remove:return
/(pid == $target || ppid == $target) && self->sys_wall/
{
	this->wall = timestamp - self->sys_wall;
	this->cpu = vtimestamp - self->sys_cpu;
	@sys_returns[execname, probefunc] = count();
	@sys_wall_ns[execname, probefunc] = sum(this->wall);
	@sys_cpu_ns[execname, probefunc] = sum(this->cpu);
	@sys_invalid_cpu[execname, probefunc] = sum(this->cpu > this->wall);
	@sys_wall_us[execname, probefunc] = quantize(this->wall / 1000);
	self->sys_wall = 0;
	self->sys_cpu = 0;
}

/* Include asynchronous teardown on taskqueue threads, filtered by jail name.
 * Track every entry's nesting so an unrelated nested prison cannot consume a
 * matching outer function's timestamp. FBT probes may be absent/inlined; -Z
 * permits that. These are inclusive times and MUST NOT be added together.
 */
fbt::prison_deref:entry,
fbt::prison_deref_kill:entry,
fbt::prison_complete:entry,
fbt::prison_jid_remove:entry
{
	self->depth[probefunc]++;
	self->start[probefunc, self->depth[probefunc]] =
	    substr(stringof(((struct prison *)arg0)->pr_name), 0,
	    strlen(bench_prefix)) == bench_prefix ? timestamp : 0;
}

/* The generated RB remove function takes the prison as its second argument. */
fbt::prison_jid_tree_RB_REMOVE:entry
{
	self->depth[probefunc]++;
	self->start[probefunc, self->depth[probefunc]] =
	    substr(stringof(((struct prison *)arg1)->pr_name), 0,
	    strlen(bench_prefix)) == bench_prefix ? timestamp : 0;
}

fbt::prison_deref:return,
fbt::prison_deref_kill:return,
fbt::prison_complete:return,
fbt::prison_jid_remove:return,
fbt::prison_jid_tree_RB_REMOVE:return
/self->depth[probefunc] && self->start[probefunc, self->depth[probefunc]]/
{
	this->elapsed = timestamp - self->start[probefunc, self->depth[probefunc]];
	@kernel_calls[probefunc] = count();
	@kernel_ns[probefunc] = sum(this->elapsed);
	@kernel_us[probefunc] = quantize(this->elapsed / 1000);
}

fbt::prison_deref:return,
fbt::prison_deref_kill:return,
fbt::prison_complete:return,
fbt::prison_jid_remove:return,
fbt::prison_jid_tree_RB_REMOVE:return
/self->depth[probefunc]/
{
	self->start[probefunc, self->depth[probefunc]] = 0;
	self->depth[probefunc]--;
}

/* System-wide lock waits during this cleanup, matching allprison_wait.d. */
lockstat:::sx-block,
lockstat:::sx-spin
/arg0 == (uintptr_t)&`allprison_lock/
{
	@lock_events[execname, probename, arg2] = count();
	@lock_ns[execname, probename, arg2] = sum(arg1);
}

END
{
	printf("Syscalls: executable, function; compare entry/return counts\n");
	printa("%s %s entries=%@d\n", @sys_entries);
	printa("%s %s returns=%@d\n", @sys_returns);
	printa("%s %s elapsed_ns=%@d\n", @sys_wall_ns);
	printa("%s %s cpu_ns=%@d\n", @sys_cpu_ns);
	printa("%s %s cpu_gt_elapsed_samples=%@d\n", @sys_invalid_cpu);
	printa("%s %s elapsed microseconds:\n%@d\n", @sys_wall_us);
	printf("Kernel functions: benchmark prefix only; inclusive times\n");
	printa("%s calls=%@d\n", @kernel_calls);
	printa("%s elapsed_ns=%@d\n", @kernel_ns);
	printa("%s microseconds:\n%@d\n", @kernel_us);
	printf("System-wide allprison waits: executable, probe, mode (0=writer, 1=reader)\n");
	printa("%s %s mode=%d events=%@d\n", @lock_events);
	printa("%s %s mode=%d elapsed_ns=%@d\n", @lock_ns);
}
