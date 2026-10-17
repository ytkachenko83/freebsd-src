#!/usr/sbin/dtrace -s
/* System-wide waits during -c command. Arguments match this source tree. */
#pragma D option quiet

lockstat:::sx-block,
lockstat:::sx-spin
/arg0 == (uintptr_t)&`allprison_lock/
{
	/* arg1: nanoseconds; arg2: requested mode (writer=0, reader=1). */
	@events[execname, probename, arg2] = count();
	@wait_ns[execname, probename, arg2] = sum(arg1);
	@wait_us[execname, probename, arg2] = quantize(arg1 / 1000);
}

END
{
	printf("allprison waits: process, probe, requested mode (0=writer, 1=reader)\n");
	printa("%s %s mode=%d events=%@d\n", @events);
	printa("%s %s mode=%d total_ns=%@d\n", @wait_ns);
	printa("%s %s mode=%d microseconds:\n%@d\n", @wait_us);
}
