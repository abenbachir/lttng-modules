#ifndef CONFIG_UID16

#define OVERRIDE_sys_getgroups16
#define OVERRIDE_sys_setgroups16
#define OVERRIDE_sys_lchown16
#define OVERRIDE_sys_getresuid16
#define OVERRIDE_sys_getresgid16
#define OVERRIDE_sys_chown16

#define OVERRIDE_TABLE_sys_getgroups16
#define OVERRIDE_TABLE_sys_setgroups16
#define OVERRIDE_TABLE_sys_lchown16
#define OVERRIDE_TABLE_sys_getresuid16
#define OVERRIDE_TABLE_sys_getresgid16
#define OVERRIDE_TABLE_sys_chown16

#endif