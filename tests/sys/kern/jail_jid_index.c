/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Yuri Tkachenko
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/jail.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <atf-c.h>
#include <jail.h>

#define BASE_LOOKUP_ATTEMPTS 100
#define RND_UPPER_BOUND 400000
#define TEST_JID_FILE "jail_jid_test.lst"
#define JAIL_PREFIX "jail_jid"
#define JAIL_NAME(suffix) JAIL_PREFIX suffix
#define ABSENT_JAIL_BY_JID(jid, flag) \
(get_jail_by_jid(jid, flag, NULL) == -1 && \
	errno == ENOENT)
#define ABSENT_JAIL_BY_JID_0(jid) ABSENT_JAIL_BY_JID(jid, 0)
#define NO_JAIL_LOOKUP_OVERFLOW \
(get_jail_by_lastjid(2147483647, 0, NULL) == -1 && \
	errno == ENOENT)

struct jid_node
{
	int jid;
	struct jid_node *next;
};

struct jail_fixture
{
	int parent;
	int a;
	int b;
	int outside;
	int base;
};

static struct jid_node *
push(struct jid_node *head, int jid)
{
	struct jid_node *node = malloc(sizeof(*node));
	if (node == NULL) {
		return (NULL);
	}

	node->jid = jid;
	node->next = head;

	return (node);
}

static int
find_jid(struct jid_node *head, int jid)
{
	struct jid_node *node;

	if (head == NULL) {
		return (0);
	}

	node = head;
	while (node != NULL) {
		if (node->jid == jid)
			return (1);
		node = node->next;
	}
	return (0);
}

static void
delete_jid_nodes(struct jid_node *head) {
	struct jid_node *node;

	while (head != NULL) {
		node = head;
		head = node->next;
		free(node);
	}
}

/* Create jail; returns jid or -1 when error */
static int
create_jail(int jid, const char *name, int children_max, int incl_bad_param)
{
	char children_max_str[2], jid_str[12];
	int closed, written;
	FILE *fp;

	snprintf(children_max_str, sizeof(children_max_str),
			"%d", children_max);
	snprintf(jid_str, sizeof(jid_str), "%d", jid);

	if (incl_bad_param)
		jid = jail_setv(JAIL_CREATE,
			"jid", jid_str,
			"name", name,
			"persist", "true",
			"path", "/",
			"host", "inherit",
			"ip4", "disable",
			"ip6", "disable",
			"children.max", children_max_str,
			"jid_index_test_unknown_parameter", "1",
			NULL
			);
	else
		jid = jail_setv(JAIL_CREATE,
			"jid", jid_str,
			"name", name,
			"persist", "true",
			"path", "/",
			"host", "inherit",
			"ip4", "disable",
			"ip6", "disable",
			"children.max", children_max_str,
			NULL
			);
	if (jid > -1) {
		fp = fopen(TEST_JID_FILE, "a");
		if (fp == NULL)
			goto cleanup_jail;
		written = fwrite(&jid, sizeof(jid), 1, fp);
		closed = fclose(fp);
		if (closed != 0 || written == 0)
			goto cleanup_jail;
		return (jid);

		cleanup_jail:
		jail_remove(jid);
		errno = EIO;
		jid = -1;
	}

	return (jid);
}

/* Return -1 with errno set if the record cannot be found or updated. */
static int
remove_journal_entry(int jid)
{
	FILE *fp;
	long offset;
	size_t nread;
	int j, error;

	fp = fopen(TEST_JID_FILE, "r+");
	if (fp == NULL)
		return (-1);
	error = 0;
	for (offset = 0; ; offset += sizeof(j)) {
		errno = 0;
		nread = fread(&j, 1, sizeof(j), fp);
		if (nread != sizeof(j)) {
			if (ferror(fp))
				error = errno != 0 ? errno : EIO;
			else
				error = nread == 0 ? ENOENT : EIO;
			break;
		}
		if (j != jid)
			continue;
		if (fseek(fp, offset, SEEK_SET) != 0) {
			error = errno;
			break;
		}
		j = -1;
		errno = 0;
		if (fwrite(&j, sizeof(j), 1, fp) != 1)
			error = errno != 0 ? errno : EIO;
		break;
	}
	if (fclose(fp) != 0 && error == 0)
		error = errno;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (0);
}

/* remove jail and remove it from journal by setting jid record to -1 */
static void
purge_jail(int jid)
{
	if (jail_remove(jid) != 0) {
		ATF_CHECK_MSG(0, "jail_remove(%d): %s", jid, strerror(errno));
	} else {
		ATF_REQUIRE_MSG(remove_journal_entry(jid) == 0,
		    "remove_journal_entry(%d): %s", jid, strerror(errno));
	}
}

static int
get_jail_by_jid(int jid, int flags, char *jail_name)
{
	char jid_str[12];

	snprintf(jid_str, sizeof(jid_str), "%d", jid);
	if (jail_name == NULL) {
		jid = jail_getv(flags,
			"jid", jid_str,
			NULL
			);
	} else {
		jid = jail_getv(flags,
			"jid", jid_str,
			"name", jail_name,
			NULL
			);
	}
	return (jid);
}

static int
get_jail_by_lastjid(int jid, int flags, char *jail_name)
{
	char jid_str[12];

	snprintf(jid_str, sizeof(jid_str), "%d", jid);
	if (jail_name == NULL) {
		jid = jail_getv(flags,
			"lastjid", jid_str,
			NULL
			);
	} else {
		jid = jail_getv(flags,
			"lastjid", jid_str,
			"name", jail_name,
			NULL
			);
	}
	return (jid);
}

static struct jid_node *
walk_jails(int start, int flags)
{
	struct jid_node *head;
	int jid;

	head = malloc(sizeof(*head));
	if (head == NULL) {
		return (NULL);
	}
	head->jid = -1;
	head->next = NULL;

	for (;; start = jid) {
		jid = get_jail_by_lastjid(start, flags, NULL);
		if (jid == -1) {
			if (errno == ENOENT)
				return (head);
			errno = EINVAL;
			return (NULL);
		}
		if (jid <= start) {
			errno = EINVAL;
			return (NULL);
		}
		head = push(head, jid);
		if (head == NULL) {
			errno = EINVAL;
			return (NULL);
		}
	}
}

static int
fork_check(int parent_jid, int a_jid, int b_jid, int outside_jid)
{
	pid_t pid;
	int stat_loc, passed;
	struct jid_node *jids;

	pid = fork();
	if (pid == 0) {
		if (jail_attach(parent_jid) == 0 &&
			get_jail_by_jid(a_jid, 0, NULL) == a_jid &&
			ABSENT_JAIL_BY_JID_0(parent_jid) &&
			ABSENT_JAIL_BY_JID_0(outside_jid)
			) {
			jids = walk_jails(0, 0);
			passed = find_jid(jids, a_jid) && find_jid(jids, b_jid);
			delete_jid_nodes(jids);
			if (passed)
				exit(EXIT_SUCCESS);
		}
		exit(EXIT_FAILURE);
	} else if (pid == -1) {
		return (-1);
	}
	while (waitpid(pid, &stat_loc, 0) == -1) {
		if (errno != EINTR)
			return (-1);
	}
	return (WIFEXITED(stat_loc) && WEXITSTATUS(stat_loc) == EXIT_SUCCESS
			? 0 : -1);
}

/*
 * Retain a jailed socket credential in the host
 * until the returned FD closes.
 */
static int
held_socket(int jid)
{
	union {
		struct cmsghdr align;
		char buffer[CMSG_SPACE(sizeof(int))];
	} control;
	struct msghdr msg_hdr;
	struct iovec iov;
	struct cmsghdr *cmsg;
	pid_t pid, waited;
	ssize_t n;
	int sv[2], sock_fd, received_fd, status, error;
	char byte;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		return (-1);
	pid = fork();
	if (pid == -1) {
		error = errno;
		close(sv[0]);
		close(sv[1]);
		errno = error;
		return (-1);
	}

	memset(&msg_hdr, 0, sizeof(msg_hdr));
	memset(&control, 0, sizeof(control));
	byte = 'x';
	iov.iov_base = &byte;
	iov.iov_len = sizeof(byte);
	msg_hdr.msg_iov = &iov;
	msg_hdr.msg_iovlen = 1;
	msg_hdr.msg_control = control.buffer;
	msg_hdr.msg_controllen = sizeof(control.buffer);

	if (pid == 0) {
		close(sv[0]);
		if (jail_attach(jid) == -1)
			_exit(EXIT_FAILURE);
		sock_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
		if (sock_fd == -1)
			_exit(EXIT_FAILURE);
		cmsg = CMSG_FIRSTHDR(&msg_hdr);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(sock_fd));
		memcpy(CMSG_DATA(cmsg), &sock_fd, sizeof(sock_fd));
		do {
			n = sendmsg(sv[1], &msg_hdr, 0);
		} while (n == -1 && errno == EINTR);
		close(sock_fd);
		close(sv[1]);
		_exit(n == sizeof(byte) ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	close(sv[1]);
	received_fd = -1;
	error = 0;
	do {
		/* recvmsg() updates these fields; restore them before a retry. */
		msg_hdr.msg_controllen = sizeof(control.buffer);
		msg_hdr.msg_flags = 0;
		n = recvmsg(sv[0], &msg_hdr, 0);
	} while (n == -1 && errno == EINTR);
	if (n == -1)
		error = errno;
	else {
		/* Close any extra received rights even if the message is invalid. */
		for (cmsg = CMSG_FIRSTHDR(&msg_hdr); cmsg != NULL;
		    cmsg = CMSG_NXTHDR(&msg_hdr, cmsg)) {
			size_t len, offset;
			int fd;

			if (cmsg->cmsg_level != SOL_SOCKET ||
			    cmsg->cmsg_type != SCM_RIGHTS)
				continue;
			if (cmsg->cmsg_len < CMSG_LEN(0)) {
				error = EIO;
				break;
			}
			len = cmsg->cmsg_len - CMSG_LEN(0);
			if (len % sizeof(fd) != 0)
				error = EIO;
			for (offset = 0; offset + sizeof(fd) <= len;
			    offset += sizeof(fd)) {
				memcpy(&fd, (char *)CMSG_DATA(cmsg) + offset,
				    sizeof(fd));
				if (received_fd == -1)
					received_fd = fd;
				else {
					close(fd);
					error = EIO;
				}
			}
		}
		if (n != sizeof(byte) || byte != 'x' || received_fd == -1 ||
		    (msg_hdr.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0)
			error = EIO;
	}
	close(sv[0]);
	do {
		waited = waitpid(pid, &status, 0);
	} while (waited == -1 && errno == EINTR);
	if (waited == -1) {
		if (error == 0)
			error = errno;
	} else if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS) {
		if (error == 0)
			error = EIO;
	}
	if (error != 0) {
		if (received_fd != -1)
			close(received_fd);
		errno = error;
		return (-1);
	}
	return (received_fd);
}

static int
wait_absent(int jid)
{
	struct timespec curr, start, sleep_ts;
	double start_secs, curr_secs;

	sleep_ts.tv_sec = (time_t)0;
	sleep_ts.tv_nsec = 2e7;

	clock_gettime(CLOCK_MONOTONIC, &start);
	start_secs = start.tv_sec + (double)start.tv_nsec / 1e9;
	while (!(ABSENT_JAIL_BY_JID(jid, JAIL_DYING))) {
		clock_gettime(CLOCK_MONOTONIC, &curr);
		curr_secs = curr.tv_sec + (double)curr.tv_nsec / 1e9;
		if (curr_secs - start_secs > 10 || nanosleep(&sleep_ts, NULL) < 0)
			return (-1);
	}
	return (0);
}

static void
setup_jails(struct jail_fixture *fixture)
{
	int i, j;

	srand((unsigned)time(NULL));

	for (i = 0; i < BASE_LOOKUP_ATTEMPTS; i++) {
		fixture->base = rand() % RND_UPPER_BOUND;
		for (j = 0; j < 8; j++) {
			if (!(ABSENT_JAIL_BY_JID(fixture->base + j, JAIL_DYING)))
				break;
		}
		if (j == 8)
			break;
	}
	fixture->parent = create_jail(fixture->base, JAIL_PREFIX, 4, 0);
	ATF_REQUIRE_MSG(fixture->parent != -1, "parent create_jail: %s", jail_errmsg);
	fixture->a = create_jail(fixture->base + 2, JAIL_NAME(".a"), 0, 0);
	ATF_REQUIRE_MSG(fixture->a != -1, "create_jail[a]: %s", jail_errmsg);
	fixture->b = create_jail(fixture->base + 4, JAIL_NAME(".b"), 0, 0);
	ATF_REQUIRE_MSG(fixture->b != -1, "create_jail[b]: %s", jail_errmsg);
	fixture->outside = create_jail(fixture->base + 6, JAIL_NAME("_outside"), 0, 0);
	ATF_REQUIRE_MSG(fixture->outside != -1, "create_jail[outside]: %s", jail_errmsg);
}

static void
cleanup_journal(void)
{
	FILE *fp;
	int jid;
	int failed = 0;
	long offset;

	fp = fopen(TEST_JID_FILE, "r");
	if (fp != NULL) {
		ATF_REQUIRE(fp != NULL);
		if (fseek(fp, 0, SEEK_END) != 0)
			goto io_error;
		offset = ftell(fp);
		if (offset < 0 || offset % sizeof(jid) != 0)
			goto io_error;

		while (offset > 0) {
			offset -= sizeof(jid);
			if (fseek(fp, offset, SEEK_SET) != 0 ||
				fread(&jid, sizeof(jid), 1, fp) != 1)
				goto io_error;
			if (jid > -1 && jail_remove(jid) != 0 && errno != ENOENT) {
				ATF_CHECK_MSG(0, "jail_remove(%d): %s", jid, strerror(errno));
				failed = 1;
			}
		}
		fclose(fp);
		if (!failed)
			remove(TEST_JID_FILE);
		return;

		io_error:
		ATF_CHECK_MSG(0, "Unable to read jid tracker - %s", TEST_JID_FILE);
		fclose(fp);
	}
}

ATF_TC_WITH_CLEANUP(lookup_enumeration);
ATF_TC_HEAD(lookup_enumeration, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "JID lookup and enumeration with sparse IDs and boundary cursors");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(lookup_enumeration, tc)
{
	struct jail_fixture fixture = {};
	int ret;
	char jail_name[MAXHOSTNAMELEN];
	struct jid_node *jids;

	setup_jails(&fixture);

	ATF_REQUIRE_MSG(get_jail_by_jid(fixture.parent, 0, jail_name) != -1,
		"get_jail: %s", jail_errmsg);
	ATF_REQUIRE_MSG(strcmp(JAIL_PREFIX, jail_name) == 0,
		"failed: %s != %s", JAIL_PREFIX, jail_name);
	ATF_REQUIRE_MSG(get_jail_by_jid(fixture.a, 0, jail_name) != -1,
		"get_jail[a]: %s", jail_errmsg);
	ATF_REQUIRE(strcmp(JAIL_NAME(".a"), jail_name) == 0);
	ATF_REQUIRE(ABSENT_JAIL_BY_JID_0(fixture.base + 1));
	ATF_REQUIRE(get_jail_by_lastjid(fixture.base + 1, 0, NULL) == fixture.a);
	ATF_REQUIRE(get_jail_by_lastjid(fixture.a, 0, NULL) == fixture.b);
	ATF_REQUIRE(NO_JAIL_LOOKUP_OVERFLOW);
	jids = walk_jails(-1, 0);
	ret = find_jid(jids, fixture.parent);
	delete_jid_nodes(jids);
	ATF_REQUIRE_MSG(ret, "Unable to find parent jid: %d", fixture.parent);
}
ATF_TC_CLEANUP(lookup_enumeration, tc)
{
	cleanup_journal();
}

ATF_TC_WITH_CLEANUP(nested_visibility);
ATF_TC_HEAD(nested_visibility, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "JID lookup and enumeration visibility from a parent jail");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(nested_visibility, tc)
{
	struct jail_fixture fixture;
	int ret;

	setup_jails(&fixture);
	ret = fork_check(fixture.parent, fixture.a, fixture.b, fixture.outside);
	ATF_REQUIRE_MSG(ret == 0, "jail_attach check via fork failed");
}
ATF_TC_CLEANUP(nested_visibility, tc)
{
	cleanup_journal();
}

ATF_TC_WITH_CLEANUP(enumeration_after_removal);
ATF_TC_HEAD(enumeration_after_removal, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "JID enumeration after removing the jail used as a cursor");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(enumeration_after_removal, tc)
{
	struct jail_fixture fixture;

	setup_jails(&fixture);
	ATF_REQUIRE(create_jail(fixture.base + 1, JAIL_NAME("_failed"), 0, 1) == -1);
	ATF_REQUIRE(wait_absent(fixture.base + 1) == 0);
	purge_jail(fixture.a);
	ATF_REQUIRE(wait_absent(fixture.a) == 0);
	ATF_REQUIRE(get_jail_by_lastjid(fixture.a, 0, NULL) == fixture.b);
	ATF_REQUIRE(get_jail_by_lastjid(fixture.base + 1, 0, NULL) == fixture.b);
}
ATF_TC_CLEANUP(enumeration_after_removal, tc)
{
	cleanup_journal();
}

ATF_TC_WITH_CLEANUP(dying_jid_reuse);
ATF_TC_HEAD(dying_jid_reuse, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Dying jail renumbering, JID reuse, and final release");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(dying_jid_reuse, tc)
{
	struct jail_fixture fixture;
	int i, old_jid, renamed_jid, held_fd;
	char jail_name[MAXHOSTNAMELEN];
	struct jid_node *jids;

	setup_jails(&fixture);
	old_jid = create_jail(fixture.base + 1, JAIL_NAME("_old"), 0, 0);
	ATF_REQUIRE(old_jid != -1);
	held_fd = held_socket(old_jid);
	ATF_REQUIRE_MSG(held_fd != -1,
		"Unable to hold socket, dying jail won't be reproduced");
	purge_jail(old_jid);
	ATF_REQUIRE(get_jail_by_jid(old_jid, JAIL_DYING, jail_name) != -1 &&
		strcmp(JAIL_NAME("_old"), jail_name) == 0);
	ATF_REQUIRE(ABSENT_JAIL_BY_JID_0(old_jid));
	ATF_REQUIRE(create_jail(old_jid, JAIL_NAME("_replacement"), 0, 0) != -1);
	renamed_jid = jail_getv(JAIL_DYING, "name", JAIL_NAME("_old"), NULL);
	ATF_REQUIRE(renamed_jid != old_jid);
	ATF_REQUIRE(get_jail_by_jid(old_jid, 0, jail_name) != -1 &&
		strcmp(JAIL_NAME("_replacement"), jail_name) == 0
		);
	ATF_REQUIRE(get_jail_by_jid(renamed_jid, JAIL_DYING, jail_name) != -1 &&
		strcmp(JAIL_NAME("_old"), jail_name) == 0
		);
	ATF_REQUIRE(ABSENT_JAIL_BY_JID_0(renamed_jid));
	jids = walk_jails(0, JAIL_DYING);
	i = find_jid(jids, renamed_jid);
	delete_jid_nodes(jids);
	ATF_REQUIRE_MSG(i, "Unable to find dying jail(%d)", renamed_jid);
	ATF_REQUIRE(close(held_fd) == 0);
	ATF_REQUIRE(wait_absent(renamed_jid) == 0);
}
ATF_TC_CLEANUP(dying_jid_reuse, tc)
{
	cleanup_journal();
}

ATF_TC_WITH_CLEANUP(subtree_removal);
ATF_TC_HEAD(subtree_removal, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Parent removal destroys its subtree and preserves unrelated jails");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(subtree_removal, tc)
{
	struct jail_fixture fixture;
	char jail_name[MAXHOSTNAMELEN];

	setup_jails(&fixture);
	purge_jail(fixture.parent);
	ATF_REQUIRE(wait_absent(fixture.parent) == 0);
	ATF_REQUIRE(wait_absent(fixture.b) == 0);
	ATF_REQUIRE(wait_absent(fixture.a) == 0);
	ATF_REQUIRE_MSG(remove_journal_entry(fixture.b) == 0,
	    "remove_journal_entry(%d): %s", fixture.b, strerror(errno));
	ATF_REQUIRE_MSG(remove_journal_entry(fixture.a) == 0,
	    "remove_journal_entry(%d): %s", fixture.a, strerror(errno));
	ATF_REQUIRE(get_jail_by_jid(fixture.outside, 0, jail_name) != -1 &&
		strcmp(JAIL_NAME("_outside"), jail_name) == 0);
}
ATF_TC_CLEANUP(subtree_removal, tc)
{
	cleanup_journal();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, lookup_enumeration);
	ATF_TP_ADD_TC(tp, nested_visibility);
	ATF_TP_ADD_TC(tp, enumeration_after_removal);
	ATF_TP_ADD_TC(tp, dying_jid_reuse);
	ATF_TP_ADD_TC(tp, subtree_removal);
	return (atf_no_error());
}
