/*
 * privilege.c - Privilege dropping for udnsfilter
 *
 * This file implements secure privilege dropping after binding to
 * privileged ports. Ensures privileges cannot be regained.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <sys/types.h>

#include "privilege.h"

/**
 * privilege_drop() - Drop root privileges
 * @user: Username to switch to (NULL for "nobody")
 * @group: Group name to switch to (NULL for "nogroup")
 *
 * Drops root privileges to the specified user and group. Sets supplementary
 * groups and verifies privileges cannot be regained.
 *
 * Return: 0 on success, -1 on error
 */
int privilege_drop(const char *user, const char *group)
{
	struct passwd *pw = NULL;
	struct group *gr = NULL;
	uid_t uid;
	gid_t gid;

	if (geteuid() != 0) {
		fprintf(stderr, "Not running as root, skipping privilege drop\n");
		return 0;
	}

	/* Default to nobody:nogroup */
	if (!user || !user[0])
		user = "nobody";

	if (!group || !group[0])
		group = "nogroup";

	/* Lookup user and group IDs */
	pw = getpwnam(user);
	if (!pw) {
		fprintf(stderr, "User '%s' not found: %s\n", user, strerror(errno));
		return -1;
	}
	uid = pw->pw_uid;

	gr = getgrnam(group);
	if (!gr) {
		fprintf(stderr, "Group '%s' not found: %s\n", group, strerror(errno));
		return -1;
	}
	gid = gr->gr_gid;

	/* Set supplementary groups */
	if (initgroups(user, gid) < 0) {
		fprintf(stderr, "initgroups failed: %s\n", strerror(errno));
		return -1;
	}

	/* Drop group privileges */
	if (setgid(gid) < 0) {
		fprintf(stderr, "setgid failed: %s\n", strerror(errno));
		return -1;
	}

	/* Drop user privileges */
	if (setuid(uid) < 0) {
		fprintf(stderr, "setuid failed: %s\n", strerror(errno));
		return -1;
	}

	/* Verify privileges cannot be regained */
	if (setuid(0) == 0 || seteuid(0) == 0) {
		fprintf(stderr, "Failed to permanently drop privileges\n");
		return -1;
	}

	fprintf(stderr, "Dropped privileges to %s:%s (uid=%d, gid=%d)\n",
	        user, group, uid, gid);

	return 0;
}
