# SPDX-License-Identifier: BSD-2-Clause

atf_test_case lookup_lifecycle cleanup
lookup_lifecycle_head()
{
	atf_set descr "JID lookup, enumeration, visibility and index lifecycle"
	atf_set require.user root
	atf_set require.progs "python3 jail jls sysctl"
	atf_set timeout 120
}
lookup_lifecycle_body()
{
	if [ "$(sysctl -n security.jail.jailed)" != 0 ]; then
		atf_skip "Requires the host jail namespace"
	fi
	atf_check -s exit:0 -o match:"PASS subtree removal" -e empty \
	    env JID_INDEX_TEST_JOURNAL="$(pwd)/jail_jid_index.names" \
	    python3 "$(atf_get_srcdir)/jail_jid_index.py"
}
lookup_lifecycle_cleanup()
{
	if [ -f jail_jid_index.names ]; then
		while IFS= read -r name; do
			case "$name" in
			jididx_*) jail -r "$name" >/dev/null 2>&1 ;;
			esac
		done < jail_jid_index.names
	fi
	return 0
}

atf_init_test_cases()
{
	atf_add_test_case lookup_lifecycle
}
