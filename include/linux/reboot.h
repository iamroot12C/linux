#ifndef _LINUX_REBOOT_H
#define _LINUX_REBOOT_H


#include <linux/notifier.h>
#include <uapi/linux/reboot.h>

#define SYS_DOWN	0x0001	/* Notify of system down */
#define SYS_RESTART	SYS_DOWN
#define SYS_HALT	0x0002	/* Notify of system halt */
#define SYS_POWER_OFF	0x0003	/* Notify of system power off */

enum reboot_mode {
	REBOOT_COLD = 0,	// 일반적인 파워 온/오프, 전원버튼 누르는거
	REBOOT_WARM,		// 와치독에 의해서 재부팅되는거,일부HW를 리셋에 제외
	REBOOT_HARD,		// 칩에 연결된 하드웨어 리셋, PC에서 리셋버튼
	REBOOT_SOFT,		// SW에 의한 리셋, ctrl+alt+del
	REBOOT_GPIO,		// GPIO 시그널에의한 리셋
};
extern enum reboot_mode reboot_mode;

enum reboot_type {
	BOOT_TRIPLE	= 't',
	BOOT_KBD	= 'k',
	BOOT_BIOS	= 'b',
	BOOT_ACPI	= 'a',
	BOOT_EFI	= 'e',
	BOOT_CF9_FORCE	= 'p',
	BOOT_CF9_SAFE	= 'q',
};
extern enum reboot_type reboot_type;

extern int reboot_default;
extern int reboot_cpu;
extern int reboot_force;


extern int register_reboot_notifier(struct notifier_block *);
extern int unregister_reboot_notifier(struct notifier_block *);

extern int register_restart_handler(struct notifier_block *);
extern int unregister_restart_handler(struct notifier_block *);
extern void do_kernel_restart(char *cmd);

/*
 * Architecture-specific implementations of sys_reboot commands.
 */

extern void migrate_to_reboot_cpu(void);
extern void machine_restart(char *cmd);
extern void machine_halt(void);
extern void machine_power_off(void);

extern void machine_shutdown(void);
struct pt_regs;
extern void machine_crash_shutdown(struct pt_regs *);

/*
 * Architecture independent implemenations of sys_reboot commands.
 */

extern void kernel_restart_prepare(char *cmd);
extern void kernel_restart(char *cmd);
extern void kernel_halt(void);
extern void kernel_power_off(void);

extern int C_A_D; /* for sysctl */
void ctrl_alt_del(void);

#define POWEROFF_CMD_PATH_LEN	256
extern char poweroff_cmd[POWEROFF_CMD_PATH_LEN];

extern int orderly_poweroff(bool force);

/*
 * Emergency restart, callable from an interrupt handler.
 */

extern void emergency_restart(void);
#include <asm/emergency-restart.h>

#endif /* _LINUX_REBOOT_H */
