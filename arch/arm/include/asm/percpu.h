/*
 * Copyright 2012 Calxeda, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef _ASM_ARM_PERCPU_H_
#define _ASM_ARM_PERCPU_H_

/*
 * Same as asm-generic/percpu.h, except that we store the per cpu offset
 * in the TPIDRPRW. TPIDRPRW only exists on V6K and V7
 */
#if defined(CONFIG_SMP) && !defined(CONFIG_CPU_V6)
static inline void set_my_cpu_offset(unsigned long off)
{
	/* Set TPIDRPRW */
	asm volatile("mcr p15, 0, %0, c13, c0, 4" : : "r" (off) : "memory");	// 어셈블리코드가 메모리를 변경할 것이라고 알림, to compiler
																			// off값을 r0에 저장, r0의 값을 코프로세서 c13->c0->4 에다가 저장.
																			// register offset(레지스터 번호)
																			// off에 들어있는 cpu코어는 priviliged only 스레드만 동작시킨다.
																			// 이렇게 하는 이유는 cpu_per_offset 를 가져올 때 위의 방식대로 가져오는 경우 기존에 비해 더 적은 수의 명령어를 이용하여 가져오게 되어서 결과적으로 성능 향상(약 1.4%)을 불러오게 되어서 이다.
																			// off => CPU_Stack Pointer
}

static inline unsigned long __my_cpu_offset(void)
{
	unsigned long off;

	/*
	 * Read TPIDRPRW.
	 * We want to allow caching the value, so avoid using volatile and
	 * instead use a fake stack read to hazard against barrier().
	 */
	asm("mrc p15, 0, %0, c13, c0, 4" : "=r" (off)
		: "Q" (*(const unsigned long *)current_stack_pointer));  

	return off;
}
#define __my_cpu_offset __my_cpu_offset()
#else
#define set_my_cpu_offset(x)	do {} while(0)

#endif /* CONFIG_SMP */

#include <asm-generic/percpu.h>

#endif /* _ASM_ARM_PERCPU_H_ */
