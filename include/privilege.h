/*
 * privilege.h - Privilege dropping header
 */

#ifndef __PRIVILEGE_H
#define __PRIVILEGE_H

int privilege_drop(const char *user, const char *group);

#endif /* __PRIVILEGE_H */
