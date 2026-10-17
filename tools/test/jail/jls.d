#!/usr/sbin/dtrace -s
/* dtrace -q -s jls.d -c '/usr/sbin/jls -n jid' */
#pragma D option quiet

syscall::jail_get:entry
/pid == $target/
{
	self->wall = timestamp;
	self->cpu = vtimestamp;
}

syscall::jail_get:return
/pid == $target && self->wall/
{
	@calls = count();
	@wall_ns = sum(timestamp - self->wall);
	@cpu_ns = sum(vtimestamp - self->cpu);
	@wall_us = quantize((timestamp - self->wall) / 1000);
	self->wall = 0;
	self->cpu = 0;
}

END
{
	printa("jail_get calls: %@d\n", @calls);
	printa("jail_get total elapsed ns: %@d\n", @wall_ns);
	printa("jail_get total on-CPU ns: %@d\n", @cpu_ns);
	printa("jail_get elapsed distribution (microseconds):\n%@d\n", @wall_us);
}
