#include <sys/types.h>
#include <sys/param.h>
#include <sys/jail.h>
#include <sys/uio.h>

#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t
nsec(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		err(1, "clock_gettime");
	return ((uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec);
}

static int
getone(const char *key, int value)
{
	/* Reconstruct iovecs: jail_get() may update their lengths. */
	int jid = 0;
	struct iovec iov[] = {
		{ .iov_base = __DECONST(void *, key), .iov_len = strlen(key) + 1 },
		{ .iov_base = &value, .iov_len = sizeof(value) },
		{ .iov_base = __DECONST(void *, "jid"), .iov_len = sizeof("jid") },
		{ .iov_base = &jid, .iov_len = sizeof(jid) },
	};

	/* Exact lookup needs only the key, with no separate output parameter. */
	if (strcmp(key, "jid") == 0)
		return (jail_get(iov, 2, 0));
	return (jail_get(iov, 4, 0));
}

int
main(int argc, char **argv)
{
	int *ids = NULL, *newids, jid, last, rounds;
	size_t count = 0, capacity = 0, calls, visible;
	uint64_t start, elapsed;
	char *end;
	long parsed;
	int exact;

	if (argc != 3 || (strcmp(argv[1], "enum") != 0 &&
	    strcmp(argv[1], "jid") != 0))
		errx(1, "usage: %s enum|jid repetitions", argv[0]);
	errno = 0;
	parsed = strtol(argv[2], &end, 10);
	if (errno != 0 || *end != '\0' || parsed < 1 || parsed > 100000)
		errx(1, "invalid repetitions");
	rounds = (int)parsed;
	exact = strcmp(argv[1], "jid") == 0;
	/* Snapshot lookup targets outside the timed exact-lookup loop. */
	if (exact) {
		last = 0;
		while ((jid = getone("lastjid", last)) >= 0) {
			if (jid <= last)
				errx(1, "non-increasing JID");
			if (count == capacity) {
				capacity = capacity == 0 ? 128 : capacity * 2;
				newids = realloc(ids, capacity * sizeof(*ids));
				if (newids == NULL)
					err(1, "realloc");
				ids = newids;
			}
			ids[count++] = jid;
			last = jid;
		}
		if (errno != ENOENT)
			err(1, "snapshot jail_get");
	}
	puts("repeat,visible_jails,syscalls,elapsed_ns");
	for (int r = 0; r < rounds; r++) {
		calls = visible = 0;
		last = 0;
		start = nsec();
		if (exact) {
			for (size_t i = 0; i < count; i++) {
				jid = getone("jid", ids[i]);
				if (jid != ids[i])
					errx(1, "JID disappeared/changed during lookup");
				calls++;
				visible++;
			}
		} else {
			for (;;) {
				jid = getone("lastjid", last);
				calls++;
				if (jid < 0) {
					if (errno != ENOENT)
						err(1, "enumeration jail_get");
					break;
				}
				if (jid <= last)
					errx(1, "non-increasing JID");
				last = jid;
				visible++;
			}
		}
		elapsed = nsec() - start;
		printf("%d,%zu,%zu,%ju\n", r, visible, calls,
		    (uintmax_t)elapsed);
	}
	free(ids);
	return (0);
}
