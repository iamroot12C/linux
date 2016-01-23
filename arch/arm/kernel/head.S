/*
 *  linux/arch/arm/kernel/head.S
 *
 *  Copyright (C) 1994-2002 Russell King
 *  Copyright (c) 2003 ARM Limited
 *  All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 *  Kernel startup code for all 32-bit CPUs
 */
#include <linux/linkage.h>
#include <linux/init.h>

/* 2015. 11. 21. (토) 14:28:43 KST
 * Source Driving presenter : Dongho Kim
 * 
 * Start Driving ...
 *
 */

#include <asm/assembler.h>
#include <asm/cp15.h>
#include <asm/domain.h>
#include <asm/ptrace.h>
#include <asm/asm-offsets.h>
#include <asm/memory.h>
#include <asm/thread_info.h>
#include <asm/pgtable.h>

#if defined(CONFIG_DEBUG_LL) && !defined(CONFIG_DEBUG_SEMIHOSTING)
#include CONFIG_DEBUG_LL_INCLUDE
#endif

/*
 * swapper_pg_dir is the virtual address of the initial page table.
 * We place the page tables 16K below KERNEL_RAM_VADDR.  Therefore, we must
 * make sure that KERNEL_RAM_VADDR is correctly set.  Currently, we expect
 * the least significant 16 bits to be 0x8000, but we could probably
 * relax this restriction to KERNEL_RAM_VADDR >= PAGE_OFFSET + 0x4000.
 */
/* PAGE_OFFSET은 Kconfig에 정의 
   : config PAGE_OFFSET 가상메모리에서의 커널의 시작주소
	hex
	default PHYS_OFFSET if !MMU 
	default 0x40000000 if VMSPLIT_1G
	default 0x80000000 if VMSPLIT_2G
	default 0xC0000000
   TEXT_OFFSET은 Makefile에 정의 커널의 엔트리 포인트
	TEXT_OFFSET := $(textofs-y)
	textofs-y	:= 0x00008000 (32K)
 */

#define KERNEL_RAM_VADDR	(PAGE_OFFSET + TEXT_OFFSET) // 3G + 32K 
#if (KERNEL_RAM_VADDR & 0xffff) != 0x8000 // TEXT_OFFSET(32K) 확인
#error KERNEL_RAM_VADDR must start at 0xXXXX8000
#endif

#ifdef CONFIG_ARM_LPAE // 이 옵션을 통해 size를 키운다 
	/* LPAE requires an additional page for the PGD */
#define PG_DIR_SIZE	0x5000
#define PMD_ORDER	3
#else
#define PG_DIR_SIZE	0x4000
#define PMD_ORDER	2
#endif

	.globl	swapper_pg_dir // 전역변수 선언
	.equ	swapper_pg_dir, KERNEL_RAM_VADDR - PG_DIR_SIZE
	.macro	pgtbl, rd, phys // 함수 선언 page table 주소를 가져오는 함수
	add	\rd, \phys, #TEXT_OFFSET
	sub	\rd, \rd, #PG_DIR_SIZE
	.endm

/*
 * Kernel startup entry point.
 * ---------------------------
 *
 * This is normally called from the decompressor code.  The requirements
 * are: MMU = off, D-cache = off, I-cache = dont care, r0 = 0,
 * r1 = machine nr, r2 = atags or dtb pointer.
 *
 * This code is mostly position independent, so if you link the kernel at
 * 0xc0008000, you call this at __pa(0xc0008000).
 *
 * See linux/arch/arm/tools/mach-types for the complete list of machine
 * numbers for r1.
 *
 * We're trying to keep crap to a minimum; DO NOT add any machine specific
 * crap here - that's what the boot loader (or in extreme, well justified
 * circumstances, zImage) is for.
 */
	.arm

	__HEAD
ENTRY(stext)
 ARM_BE8(setend	be )			@ ensure we are in BE8 mode

 THUMB(	adr	r9, BSYM(1f)	)	@ Kernel is always entered in ARM.
 THUMB(	bx	r9		)	@ If this is a Thumb-2 kernel,
 THUMB(	.thumb			)	@ switch to Thumb now.
 THUMB(1:			)

#ifdef CONFIG_ARM_VIRT_EXT
	bl	__hyp_stub_install
#endif
	@ ensure svc mode and all interrupts masked	//supervisor mode and 인터럽트 비활성화
	safe_svcmode_maskall r9				// r9를 svcnmode maskall  

	mrc	p15, 0, r9, c0, c0		@ get processor id	//r9 = processor id
	bl	__lookup_processor_type		@ r5=procinfo r9=cpuid
	movs	r10, r5				@ invalid processor (r5=0)? //move결과에 따라 N,Z flag
 THUMB( it	eq )		@ force fixup-able long branch encoding
	beq	__error_p			@ yes, error 'p'	// r5 == 0 이면 error

#ifdef CONFIG_ARM_LPAE
	mrc	p15, 0, r3, c0, c1, 4		@ read ID_MMFR0
	and	r3, r3, #0xf			@ extract VMSA support 
	// VMSA(Virtual Memory System Architecture)
	cmp	r3, #5				@ long-descriptor translation table format?
	// cmp r3 0101
 THUMB( it	lo )				@ force fixup-able long branch encoding
	blo	__error_lpae			@ only classic page table format
#endif

#ifndef CONFIG_XIP_KERNEL
	adr	r3, 2f		// r3 == 2f의 물리주소
	ldmia	r3, {r4, r8}	// r4(2f위치 가상주소), r8(PAGE_OFFSET) 
	sub	r4, r3, r4			@ (PHYS_OFFSET - PAGE_OFFSET)
	add	r8, r8, r4			@ PHYS_OFFSET
#else
	ldr	r8, =PLAT_PHYS_OFFSET		@ always constant in this case
#endif

	/*
	 * r1 = machine no, r2 = atags or dtb,
	 * r8 = phys_offset, r9 = cpuid, r10 = procinfo
	 */
	bl	__vet_atags		// atag 유효성 검사 compressd/head.S atags_to_fdt 함수와 비슷


	/* 2015. 11. 21. (토) 20:43:11 KST
	 * end driving 
	 * Dongho kim
	 */

	/* 2015. 12. 05. (토) 14:31:34 KST
	 * Source Driving presenter : Dongho Kim
	 * 
	 * Start Driving ...
	 *
	 */

#ifdef CONFIG_SMP_ON_UP
	bl	__fixup_smp	// SMP(Symmentric Multi Processing)
#endif
	/* 2015. 12. 05. (토) 20:47:07 KST
	 * end driving 
	 * Dongho kim
	 */
#ifdef CONFIG_ARM_PATCH_PHYS_VIRT

	/* 2015. 12. 12. (토) 14:31:08 KST
	 * Source Driving presenter : DH_Kim
	 * 
	 * Start Driving ...
	 *
	 */
	// TODO
	// __fixup_a_pv_table 부터 재분석 필요.
	bl	__fixup_pv_table	// physical to virtual

#endif


	/* 2016. 01. 09. (토) 20:04:13 KST */
	/* Source Driving presenter : Shim man-seop
	/* 
	/* Start Driving ...
	/*									*/

	bl	__create_page_tables

	/*
	 * The following calls CPU specific code in a position independent
	 * manner.  See arch/arm/mm/proc-*.S for details.  r10 = base of
	 * xxx_proc_info structure selected by __lookup_processor_type
	 * above.  On return, the CPU will be ready for the MMU to be
	 * turned on, and r0 will hold the CPU control register value.
	 */
		// 스택 포인터에 mmap_switched 주소를 넣어줌
	ldr	r13, =__mmap_switched		@ address to jump to after
						@ mmu has been enabled
	adr	lr, BSYM(1f)			@ return (PIC) address // .ltorg 의 주소 == PIC_ADDRESS(__enable_mmu)
	mov	r8, r4				@ set TTBR1 to swapper_pg_dir // TTBR1 에 swapper_pg_dir 을 세팅
 ARM(	add	pc, r10, #PROCINFO_INITFUNC	) // lookup_process_type 에서 어떤 #PROC_INFO 함수를 불러올지 결정!
 THUMB(	add	r12, r10, #PROCINFO_INITFUNC	) // 호출 뒤에 복귀 주소에 enable_mmu 를 지정 
 THUMB(	ret	r12				) // THUMB Mode(16bit) 일때는 mmu enable 안함
1:	b	__enable_mmu
ENDPROC(stext)
	.ltorg // 프로그램의 상수값을 저장하는 영역
#ifndef CONFIG_XIP_KERNEL
2:	.long	.
	.long	PAGE_OFFSET
#endif

/*
 * Setup the initial page tables.  We only setup the barest 
 * amount which are required to get the kernel running, which
 * generally means mapping in the kernel code.
 *
 * r8 = phys_offset, r9 = cpuid, r10 = procinfo
 *
 * Returns:
 *  r0, r3, r5-r7 corrupted
 *  r4 = page table (see ARCH_PGD_SHIFT in asm/memory.h)
 */
__create_page_tables:
	// r4 = 페이지 테이블 주소(page table), r8 = phys_offset
	//  r8 = phys_offset, r9 = cpuid, r10 = procinfo
	pgtbl	r4, r8				@ page table address

	/*
	 * Clear the swapper page table
	 */
	mov	r0, r4
	mov	r3, #0
	add	r6, r0, #PG_DIR_SIZE // PG_DIR_SIZE 만큼  230~234 라인 반복(loop)하겠다는 의미 
							 // 해당 루프의 의미 : 페이지 테이블 초기화(r3 = 0)
							 // 
1:	str	r3, [r0], #4
	str	r3, [r0], #4
	str	r3, [r0], #4
	str	r3, [r0], #4
	teq	r0, r6
	bne	1b

#ifdef CONFIG_ARM_LPAE
// 해당 옵션의 의미 : 4GB 이상 영역을 가리키기 위한 PageTable 을 Setting 해주는 Routine!!
// 2단 페이징에서 3단 페이징으로 확장
	/*
	 * Build the PGD table (first level) to point to the PMD table. A PGD
	 * entry is 64-bit wide.
	 */

	/* PAE(물리주소 확장) 옵션일때는 Page Global Directory 를 생성*/
	/* 페이징 단계가 늘어남 ! */
	//  r4 = 페이지 테이블 주소(page table), r8 = phys_offset
	//  r9 = cpuid, r10 = procinfo
	// L_PGD_SWAPPER = 마스터 page global directory?

	// 250~254 줄 의 역할 첫번째 PMD의 위치,블록 속성,개수를 설정
	// 첫번째 PGD를 setting 해주는 루틴
	// LPAE 옵션이 켜졌으므로, 0x1000만큼 페이지 크기가 커짐.
	// PageTable 시작 주소 + 0x1000 ~ PageTable 시작 주소 + 0x1000*PTRS_PER_PGD 구간 까지의 
	// PageTable을 Setting. 해당 PageTable은 4GB이상 영역(LPAE)영역을 가리키는 페이지 테이블로 setting
	mov	r0, r4
	add	r3, r4, #0x1000			@ first PGD table address(PGD+4096 == 첫번째 PMD 테이블)
	orr	r3, r3, #3			@ PGD block type // 현재 setting 된 속성 P,R/W
											 // P : 페이지 테이블이 메모리에 있는가?(1로 setting 된 경우)
										    // R/W : 페이지 테이블에 쓰기 권한이 있는가? (1인경우 읽기/쓰기 가능, 0이면 읽기 만 가능 )
	mov	r6, #4				@ PTRS_PER_PGD(PGD 엔트리 개수)
	mov	r7, #1 << (55 - 32)		@ L_PGD_SWAPPER // (L_PGD_SWAPPER 를 표현할때 상위 32bit만 표현하기 위해 사용함) 나중에 다시 봐야함!

	// r0 = 페이지 테이블(PGD) 주소
	// r3 = 첫번째 PMD 테이블 주소(하위 비트를 속성을 표기하는데 사용함)
	// r6 = PGD 의 엔트리 개수
	// r7 = L_PGD_SWAPPER (L_PGD_SWAPPER 옵션은, 페이지 테이블의 스와핑 영역을 가리키는 부분을 런타임 시점에서 미리 해제 되지 않게 보호해주는 옵션임  )

// 64bit는 페이지 테이블 1개로 표현이 되지 않으므로,
// 2개로 나눠서 표현, 23bit 영역을 setting 하는 이유 : 주소영역을 제한하기 위해서?

// 초기화 루프
1:
#ifdef CONFIG_CPU_ENDIAN_BE8
	str	r7, [r0], #4			@ set top PGD entry bits
	str	r3, [r0], #4			@ set bottom PGD entry bits
#else
	str	r3, [r0], #4			@ set bottom PGD entry bits
	str	r7, [r0], #4			@ set top PGD entry bits
#endif
	add	r3, r3, #0x1000			@ next PMD table
	subs	r6, r6, #1
	bne	1b

	add	r4, r4, #0x1000			@ point to the PMD tables
#ifdef CONFIG_CPU_ENDIAN_BE8
	add	r4, r4, #4			@ we only write the bottom word
#endif
#endif


 /* 2016. 01. 09. (토) 21:42:03 KST */
 /* Shim man seop */
 /* End Driving  */


/* 2016. 01. 16. (토) 15:19:44 KST */
/* Shim man seop */
/* Start Driving */

// 본격적으로 PageTable Setting 시작.

	// r4 = 페이지 테이블 주소(page table)
	//  r8 = phys_offset, r9 = cpuid, r10 = procinfo

	ldr	r7, [r10, #PROCINFO_MM_MMUFLAGS] @ mm_mmuflags  // procinfo 구조체의 MMU_FLAG 옵션을 가져옴.
								// DEFINE와 offset_of 매크로를 이용해서 런타임때에 상수 값을 결정!
	/*
	 * Create identity mapping to cater for __enable_mmu.
	 * This identity mapping will be removed by paging_init().
	 */
	adr	r0, __turn_mmu_on_loc // __turn_mmu_on_loc 구조체의 시작 주소를 넘겨줌
	ldmia	r0, {r3, r5, r6} 		// r3 : . , r5 : turn_mmu_on, r6 : turn_mmu_on_end
						// r7 : proc_info의 mm_mmuflag
	// 316 ~ 318 line : turn_mmu_on 주소 보정 루틴
	sub	r0, r0, r3			@ virt->phys offset
	add	r5, r5, r0			@ phys __turn_mmu_on
	add	r6, r6, r0			@ phys __turn_mmu_on_end  
	
	// r5와 r6(각각 turn_mmu_on 의 시작주소와 끝 주소)의 상위 12bit(__turn_mmu_on의 base addr)만 남김
	mov	r5, r5, lsr #SECTION_SHIFT	// SECTION_SHIFT : 20(Page Table Level : 2)
	mov	r6, r6, lsr #SECTION_SHIFT	// SECTION_SHIFT : 21(Page Table Level : 3)

	// (base_addr | flag) 의 값을 페이지 테이블에다가 넣어줌. 
	// 해당 영역은 __turn_mmu_on영역을 가리키는 페이지 테이블
	// 만약 __turn_mmu_on 의 섹션크기가 너무 경우 페이지 테이블을 추가로 할당함.(332 줄의 addlo 부분 참조)
1:	orr	r3, r7, r5, lsl #SECTION_SHIFT	@ flags + kernel base // 상위 12bit가 kernel 이미지의 끝 주소.()
	str	r3, [r4, r5, lsl #PMD_ORDER]	@ identity mapping
	cmp	r5, r6
	addlo	r5, r5, #1			@ next section
	blo	1b


	
	/*
	 * Map our RAM from the start to the end of the kernel .bss section.
	 * 커널 영역 페이지 테이블 생성 루틴.
	 */

	// r4 = page table 시작 주소
	// r7 = flag,  r8 = phys_offset(0x40000000) -> RAM 의 물리 시작 주소
	// PAGE_OFFSET -> 0xC0000000
	// PAGE_OFFSET >> (SECTION_SHIFT - PMD_ORDER) 0x3000

	add	r0, r4, #PAGE_OFFSET >> (SECTION_SHIFT - PMD_ORDER) // 0x3000을 왜 더하는 것일까?
								    // Page 시작 주소에서 0x3000 만큼 더한 위치 부터
								    // 커널의 PageTable을 생성하겠다는 의미. 
	
	// 루프를 돌면서 커널 페이지 테이블 생성
	// Page Table 크기 = 0x3000
	ldr	r6, =(_end - 1) // _end --> .bss section 의 마지막 주소
	orr	r3, r8, r7 
	add	r6, r4, r6, lsr #(SECTION_SHIFT - PMD_ORDER) // _end의 상위 12bit 주소와 base_addr을 더함.
1:	str	r3, [r0], #1 << PMD_ORDER
	add	r3, r3, #1 << SECTION_SHIFT
	cmp	r0, r6
	bls	1b

// XIP_KERNEL 부분은 PASS!!!!!!!
/*
#ifdef CONFIG_XIP_KERNEL
	/*
	 * Map the kernel image separately as it is not located in RAM.
	 */
#define XIP_START XIP_VIRT_ADDR(CONFIG_XIP_PHYS_ADDR)
	mov	r3, pc
	mov	r3, r3, lsr #SECTION_SHIFT
	orr	r3, r7, r3, lsl #SECTION_SHIFT
	add	r0, r4,  #(XIP_START & 0xff000000) >> (SECTION_SHIFT - PMD_ORDER)
	str	r3, [r0, #((XIP_START & 0x00f00000) >> SECTION_SHIFT) << PMD_ORDER]!
	ldr	r6, =(_edata_loc - 1)
	add	r0, r0, #1 << PMD_ORDER
	add	r6, r4, r6, lsr #(SECTION_SHIFT - PMD_ORDER)
1:	cmp	r0, r6
	add	r3, r3, #1 << SECTION_SHIFT
	strls	r3, [r0], #1 << PMD_ORDER
	bls	1b
#endif
*/
	/*
	 * Then map boot params address in r2 if specified.
	 * We map 2 sections in case the ATAGs/DTB crosses a section boundary.
	 */
	
	// DTB/ATAG 영역 페이지 테이블 Mapping
	// 만약 부트로더 에서 인자가 넘어오면 r2에 인자의 주소가 들어있음.
	// 이 경우에는 DTB/ATAG Mapping에 Section 2개를 차지함

	// 페이지 테이블 생성 구조는 위의 라인과 유사함.
	mov	r0, r2, lsr #SECTION_SHIFT // r0에 부트 파라미터 주소의 상위 12bit만 남김
	movs	r0, r0, lsl #SECTION_SHIFT // flag setting
					   // r0 가 0인 경우만 Z flag setting

	// Boot loader에서 파라미터(인자)가 넘어오면 DTB/ATAG 의 페이지 테이블 영역을 Setting
	subne	r3, r0, r8
	addne	r3, r3, #PAGE_OFFSET
	addne	r3, r4, r3, lsr #(SECTION_SHIFT - PMD_ORDER)
	orrne	r6, r7, r0
	strne	r6, [r3], #1 << PMD_ORDER
	addne	r6, r6, #1 << SECTION_SHIFT
	strne	r6, [r3]

// 64bit 일때는 page table을 가리키는 주소를 보정 해야함
#if defined(CONFIG_ARM_LPAE) && defined(CONFIG_CPU_ENDIAN_BE8)
	sub	r4, r4, #4			@ Fixup page table pointer
						@ for 64-bit descriptors
#endif

/* // Debug Stuff 도 패스!!!
#ifdef CONFIG_DEBUG_LL
#if !defined(CONFIG_DEBUG_ICEDCC) && !defined(CONFIG_DEBUG_SEMIHOSTING)
	/*
	 * Map in IO space for serial debugging.
	 * This allows debug messages to be output
	 * via a serial console before paging_init.
	 */
	addruart r7, r3, r0

	mov	r3, r3, lsr #SECTION_SHIFT
	mov	r3, r3, lsl #PMD_ORDER

	add	r0, r4, r3
	mov	r3, r7, lsr #SECTION_SHIFT
	ldr	r7, [r10, #PROCINFO_IO_MMUFLAGS] @ io_mmuflags
	orr	r3, r7, r3, lsl #SECTION_SHIFT
#ifdef CONFIG_ARM_LPAE
	mov	r7, #1 << (54 - 32)		@ XN
#ifdef CONFIG_CPU_ENDIAN_BE8
	str	r7, [r0], #4
	str	r3, [r0], #4
#else
	str	r3, [r0], #4
	str	r7, [r0], #4
#endif
#else
	orr	r3, r3, #PMD_SECT_XN
	str	r3, [r0], #4
#endif

#else /* CONFIG_DEBUG_ICEDCC || CONFIG_DEBUG_SEMIHOSTING */
	/* we don't need any serial debugging mappings */
	ldr	r7, [r10, #PROCINFO_IO_MMUFLAGS] @ io_mmuflags
#endif

#if defined(CONFIG_ARCH_NETWINDER) || defined(CONFIG_ARCH_CATS)
	/*
	 * If we're using the NetWinder or CATS, we also need to map
	 * in the 16550-type serial port for the debug messages
	 */
	add	r0, r4, #0xff000000 >> (SECTION_SHIFT - PMD_ORDER)
	orr	r3, r7, #0x7c000000
	str	r3, [r0]
#endif
#ifdef CONFIG_ARCH_RPC
	/*
	 * Map in screen at 0x02000000 & SCREEN2_BASE
	 * Similar reasons here - for debug.  This is
	 * only for Acorn RiscPC architectures.
	 */
	add	r0, r4, #0x02000000 >> (SECTION_SHIFT - PMD_ORDER)
	orr	r3, r7, #0x02000000
	str	r3, [r0]
	add	r0, r4, #0xd8000000 >> (SECTION_SHIFT - PMD_ORDER)
	str	r3, [r0]
#endif
#endif
****/ // 여기까지 Debug Stuff 임, 넘어갑니다.



// LPAE 옵션이 켜졌을시, 페이지 테이블을 가리키는 포인터를 을 PGD의 시작주소로 옮겨줌
#ifdef CONFIG_ARM_LPAE
	sub	r4, r4, #0x1000		@ point to the PGD table
	mov	r4, r4, lsr #ARCH_PGD_SHIFT
#endif
	ret	lr
ENDPROC(__create_page_tables)
	.ltorg
	.align
__turn_mmu_on_loc:
	.long	.
	.long	__turn_mmu_on
	.long	__turn_mmu_on_end

#if defined(CONFIG_SMP)
	.text
ENTRY(secondary_startup_arm)
	.arm
 THUMB(	adr	r9, BSYM(1f)	)	@ Kernel is entered in ARM.
 THUMB(	bx	r9		)	@ If this is a Thumb-2 kernel,
 THUMB(	.thumb			)	@ switch to Thumb now.
 THUMB(1:			)
ENTRY(secondary_startup)
	/*
	 * Common entry point for secondary CPUs.
	 *
	 * Ensure that we're in SVC mode, and IRQs are disabled.  Lookup
	 * the processor type - there is no need to check the machine type
	 * as it has already been validated by the primary processor.
	 */

 ARM_BE8(setend	be)				@ ensure we are in BE8 mode

#ifdef CONFIG_ARM_VIRT_EXT
	bl	__hyp_stub_install_secondary
#endif
	safe_svcmode_maskall r9

	mrc	p15, 0, r9, c0, c0		@ get processor id
	bl	__lookup_processor_type
	movs	r10, r5				@ invalid processor?
	moveq	r0, #'p'			@ yes, error 'p'
 THUMB( it	eq )		@ force fixup-able long branch encoding
	beq	__error_p

	/*
	 * Use the page tables supplied from  __cpu_up.
	 */
	adr	r4, __secondary_data
	ldmia	r4, {r5, r7, r12}		@ address to jump to after
	sub	lr, r4, r5			@ mmu has been enabled
	ldr	r4, [r7, lr]			@ get secondary_data.pgdir
	add	r7, r7, #4
	ldr	r8, [r7, lr]			@ get secondary_data.swapper_pg_dir
	adr	lr, BSYM(__enable_mmu)		@ return address
	mov	r13, r12			@ __secondary_switched address
 ARM(	add	pc, r10, #PROCINFO_INITFUNC	) @ initialise processor
						  @ (return control reg)
 THUMB(	add	r12, r10, #PROCINFO_INITFUNC	)
 THUMB(	ret	r12				)
ENDPROC(secondary_startup)
ENDPROC(secondary_startup_arm)

	/*
	 * r6  = &secondary_data
	 */
ENTRY(__secondary_switched)
	ldr	sp, [r7, #4]			@ get secondary_data.stack
	mov	fp, #0
	b	secondary_start_kernel
ENDPROC(__secondary_switched)

	.align

	.type	__secondary_data, %object
__secondary_data:
	.long	.
	.long	secondary_data
	.long	__secondary_switched
#endif /* defined(CONFIG_SMP) */



/*
 * Setup common bits before finally enabling the MMU.  Essentially
 * this is just loading the page table pointer and domain access
 * registers.
 *
 *  r0  = cp#15 control register
 *  r1  = machine ID
 *  r2  = atags or dtb pointer
 *  r4  = page table (see ARCH_PGD_SHIFT in asm/memory.h)
 *  r9  = processor ID
 *  r13 = *virtual* address to jump to upon completion
 */

// boot/compressed/head.S 에서 비활성화 한, I-Cache, D-Cache, Branch-Prediction, 옵션을 활성화
// CR_A -> Alignment_abort enable
// CR_C -> D-Cache Enable
// CR_Z -> Branch Prediction(분기 예측) 옵션을 활성화  
// CR_I -> I-Cache Enable
// bit가 1로 setting 되면 해당 옵션을 사용

__enable_mmu:
#if defined(CONFIG_ALIGNMENT_TRAP) && __LINUX_ARM_ARCH__ < 6
	orr	r0, r0, #CR_A 
#else
	bic	r0, r0, #CR_A
#endif
#ifdef CONFIG_CPU_DCACHE_DISABLE
	bic	r0, r0, #CR_C
#endif
#ifdef CONFIG_CPU_BPREDICT_DISABLE
	bic	r0, r0, #CR_Z
#endif
#ifdef CONFIG_CPU_ICACHE_DISABLE
	bic	r0, r0, #CR_I
#endif

// 64 bit가 아닐 때
// #define domain_val(dom,type) ( (type) << (2*(dom)))
// DOMAIN_USER -> User 메모리만 갖고있음
// DOMAIN_KERNEL -> Kernel 메모리만 갖고있음
// DOMAIN_TABLE -> PageTable 메모리?
// DOMAIN_IO -> I/O 메모리만 갖고 있음.

#ifndef CONFIG_ARM_LPAE
	
	// Domain 권한을 설정하여 r5레지스터에 넣고 이 값을 P15에 전송
	mov	r5, #(domain_val(DOMAIN_USER, DOMAIN_MANAGER) | \
		      domain_val(DOMAIN_KERNEL, DOMAIN_MANAGER) | \
		      domain_val(DOMAIN_TABLE, DOMAIN_MANAGER) | \
		      domain_val(DOMAIN_IO, DOMAIN_CLIENT))
	mcr	p15, 0, r5, c3, c0, 0		@ load domain access register // domain access register에 r5를 로드
	mcr	p15, 0, r4, c2, c0, 0		@ load page table pointer // page talbe pointer를 cp register 에 로드
#endif
	b	__turn_mmu_on
ENDPROC(__enable_mmu)

/*
 * Enable the MMU.  This completely changes the structure of the visible
 * memory space.  You will not be able to trace execution through this.
 * If you have an enquiry about this, *please* check the linux-arm-kernel
 * mailing list archives BEFORE sending another post to the list.
 *
 *  r0  = cp#15 control register
 *  r1  = machine ID
 *  r2  = atags or dtb pointer
 *  r9  = processor ID
 *  r13 = *virtual* address to jump to upon completion
 *
 * other registers depend on the function called upon completion
 */
	.align	5
	.pushsection	.idmap.text, "ax" 
					  /* 
						 .idmap 영역은 1:1 identity mapping 영역이라하여 별도의 섹션에 저장.
 						* MMU를 켜는 순간에 다음으로 수행되는 명령들이 가상주소를 얻기 위해
 						* TLB를 통해 페이지 테이블에 접근하게 되는데 이 가상주소에 대응하는
 						* 매핑이 페이지 테이블에 있어야 한다.
					   */
ENTRY(__turn_mmu_on)
	mov	r0, r0 // 명령어 수행순서(=동기화)를 보장하여, cp 명령어 실행의 오류를 방지하기위해 mov r0,r0와
			// instr_sync 를 실행
			// 쉽게 생각하여 Mutex 비스무리한거라 생각하면 될듯 싶음.
	instr_sync 	
	mcr	p15, 0, r0, c1, c0, 0		@ write control reg // r0 : enable 에서 Setting 해준 플래그를 cp15 에다가 써줌
	mrc	p15, 0, r3, c0, c0, 0		@ read id reg // id register 를 가져옴.(MIDR을 읽어옴)
						// Dummy 명령어로 추정
						// 가져오는 이유 ?
	instr_sync
	mov	r3, r3 // 명령어 수행순서를 보장하기 위해 실행하는 dummy 명령어 (위의 명령어와 역할이 같음)
	mov	r3, r13 // r13 == __mmap_switched 함수 주소
	ret	r3 // mmap_switched 함수로 분기.
__turn_mmu_on_end:
ENDPROC(__turn_mmu_on)
	.popsection


#ifdef CONFIG_SMP_ON_UP
	__HEAD
__fixup_smp:
	and	r3, r9, #0x000f0000	@ architecture version
	teq	r3, #0x000f0000		@ CPU ID supported? // teq -> xor검사
	bne	__fixup_smp_on_up	@ no, assume UP // zero flag on -> 함수호출 

	bic	r3, r9, #0x00ff0000
	bic	r3, r3, #0x0000000f	@ mask 0xff00fff0
	mov	r4, #0x41000000
	orr	r4, r4, #0x0000b000
	orr	r4, r4, #0x00000020	@ val 0x4100b020
	teq	r3, r4			@ ARM 11MPCore?
	reteq	lr			@ yes, assume SMP

	mrc	p15, 0, r0, c0, c0, 5	@ read MPIDR
	and	r0, r0, #0xc0000000	@ multiprocessing extensions and 
	teq	r0, #0x80000000		@ not part of a uniprocessor system? //uniprocess flag
	bne    __fixup_smp_on_up	@ no, assume UP

	@ Core indicates it is SMP. Check for Aegis SOC where a single
	@ Cortex-A9 CPU is present but SMP operations fault.
	mov	r4, #0x41000000
	orr	r4, r4, #0x0000c000
	orr	r4, r4, #0x00000090
	teq	r3, r4			@ Check for ARM Cortex-A9
	retne	lr			@ Not ARM Cortex-A9,

	@ If a future SoC *does* use 0x0 as the PERIPH_BASE, then the
	@ below address check will need to be #ifdef'd or equivalent
	@ for the Aegis platform.
	mrc	p15, 4, r0, c15, c0	@ get SCU base address
	teq	r0, #0x0		@ '0' on actual UP A9 hardware
	beq	__fixup_smp_on_up	@ So its an A9 UP
	ldr	r0, [r0, #4]		@ read SCU Config
ARM_BE8(rev	r0, r0)			@ byteswap if big endian
	and	r0, r0, #0x3		@ number of CPUs
	teq	r0, #0x0		@ is 1?
	retne	lr

__fixup_smp_on_up:
	adr	r0, 1f		// Memory address 
	ldmia	r0, {r3 - r5}
	sub	r3, r0, r3	// 보정검사 r3 = offset
	add	r4, r4, r3	// offset 검사
	add	r5, r5, r3
	b	__do_fixup_smp_on_up
ENDPROC(__fixup_smp)

	.align
1:	.word	.		// r3 <- symbol address : mmu on할 경우 가상주소!
	.word	__smpalt_begin	// r4
	.word	__smpalt_end	// r5

	.pushsection .data
	.globl	smp_on_up
smp_on_up:
	ALT_SMP(.long	1)	// 태그따라서 1번으로 가세요.
	ALT_UP(.long	0)
	.popsection
#endif

	.text
__do_fixup_smp_on_up: // 반복문
	cmp	r4, r5	// r4(__smpalt_begin), r5(__smpalt_end) [r4 - r5]
	reths	lr	// hs(unsiged higer or same) return lr;
	ldmia	r4!, {r0, r6}
 ARM(	str	r6, [r0, r3]	)
 THUMB(	add	r0, r0, r3	)
#ifdef __ARMEB__
 THUMB(	mov	r6, r6, ror #16	)	@ Convert word order for big-endian.
#endif
 THUMB(	strh	r6, [r0], #2	)	@ For Thumb-2, store as two halfwords
 THUMB(	mov	r6, r6, lsr #16	)	@ to be robust against misaligned r3.
 THUMB(	strh	r6, [r0]	)
	b	__do_fixup_smp_on_up
ENDPROC(__do_fixup_smp_on_up)

ENTRY(fixup_smp)
	stmfd	sp!, {r4 - r6, lr}
	mov	r4, r0
	add	r5, r0, r1
	mov	r3, #0
	bl	__do_fixup_smp_on_up
	ldmfd	sp!, {r4 - r6, pc}
ENDPROC(fixup_smp)

#ifdef __ARMEB__
#define LOW_OFFSET	0x4
#define HIGH_OFFSET	0x0
#else
#define LOW_OFFSET	0x0
#define HIGH_OFFSET	0x4
#endif

#ifdef CONFIG_ARM_PATCH_PHYS_VIRT

/* __fixup_pv_table - patch the stub instructions with the delta between
 * PHYS_OFFSET and PAGE_OFFSET, which is assumed to be 16MiB aligned and
 * can be expressed by an immediate shifter operand. The stub instruction
 * has a form of '(add|sub) rd, rn, #imm'.
 */
/*
	.align
1:	.long	.						// r3		 
	.long	__pv_table_begin		// r4
	.long	__pv_table_end			// r5
2:	.long	__pv_phys_pfn_offset	// r6
	.long	__pv_offset				// r7
  */
	__HEAD
__fixup_pv_table:
	adr	r0, 1f		// r0 <- 1f's address
	ldmia	r0, {r3-r7}
	mvn	ip, #0		// mov ip, #0xffffffff 
	subs	r3, r0, r3	@ PHYS_OFFSET + (~(PAGE_OFFSET)+1) // r0보다 r3가 더 클 경우 cc : carry clear.
															// 밑에 strcc 에 영향을 미침.
	add	r4, r4, r3	@ adjust table start address				// r3의 offset으로 r4 보정
	add	r5, r5, r3	@ adjust table end address					// r3의 offset으로 r5보정
	add	r6, r6, r3	@ adjust __pv_phys_pfn_offset address		// r3의 offset으로 r6 보정
	add	r7, r7, r3	@ adjust __pv_offset address				// r3의 offset으로 r7 보정
	mov	r0, r8, lsr #PAGE_SHIFT	@ convert to PFN // PAGE_SHIFT 12(4K = 2의 12승), PFN(Page Frame Num) 
								// r0에 페이지 프레임 개수 들어가 있음.
	str	r0, [r6]	@ save computed PHYS_OFFSET to __pv_phys_pfn_offset
								// 페이지 개수를 r6에 들어있는 주소에다가 넣고
	strcc	ip, [r7, #HIGH_OFFSET]	@ save to __pv_offset high bits 
									// delta 값이 음수가 나오는 경우 주소값 보정이 제대로 되지 않으므로, 상위비트에 -1(0xffffffff)을 넣어줌
									// r7의 상위 비트에 ip에 있는 값을 넣는다. r7은 쿼드 이기때문에 8바이트, 즉 상위는 4바이트.
	mov	r6, r3, lsr #24	@ constant for add/sub instructions	
						// r3에 있는 값을 오른쪽으로 24비트 쭉 밀고, 민것을 r6에 넣는다. r6에는 하위 8비트만 저장되어 있음.
	teq	r3, r6, lsl #24 @ must be 16MiB aligned
						// r6를 다시 왼쪽으로 24비트 밀면, 상위 8비트만 있음. 그거랑 r3랑 비교함. 둘이 같으면 0이 나옴.
						// teq는 xor연산임.
THUMB(	it	ne		@ cross section branch )
	bne	__error			// r3 랑 r6랑 일치하지않으면 error로 감. 여기 가면 busy하면서 계속 무한으로 루프돔.
						// 만약에 r3가 24비트 즉 16메가비트 로 allign안되있으면 error로 간다는 소리.
	str	r3, [r7, #LOW_OFFSET]	@ save to __pv_offset low bits
								// 이번에는 r7의 하위 비트에다가 r3 값을 저장.
								// r7에는 최종적으로 0xFFFFFFFF ??000000
	b	__fixup_a_pv_table
ENDPROC(__fixup_pv_table)

	.align
1:	.long	.						// r3		 
	.long	__pv_table_begin		// r4
	.long	__pv_table_end			// r5
2:	.long	__pv_phys_pfn_offset	// r6
	.long	__pv_offset				// r7

	.text
__fixup_a_pv_table:
	adr	r0, 3f						// 3레이블의 주소값 가져옴
	ldr	r6, [r0]					// 3레이블에 있는 _pv_offset 레이블의 주소를 r6에 저장
	add	r6, r6, r3					// r3가 피지컬이랑 페이지의오프셋의 델타값, 즉, r6를 보정해주는 것.
	ldr	r0, [r6, #HIGH_OFFSET]	@ pv_offset high word	//  r6의 상위 4바이트를 r0 에 저장
	ldr	r6, [r6, #LOW_OFFSET]	@ pv_offset low word	// r6의 하위 4바이트를 r6에 저장
	mov	r6, r6, lsr #24				// r6를 오른쪽으로 24비트 밈.
	cmn	r0, #1						// r0 에 1을 더해서 그에 맞게 상태 플래그가 슴.
									// r0 에는 0xFFFFFFFF
									// r6 에는 0x??000000	
									// 즉, r0=-1 과 1을 더하니까 0이 나오고 Z 플래그 슨다.
/*
#ifdef CONFIG_THUMB2_KERNEL // THUMMB2 MODE 일 경우 21bit를 set 할 경우 mov 명령어에서 -> mvn 명령어로 변환이 됨!
	moveq	r0, #0x200000	@ set bit 21, mov to mvn instruction
	lsls	r6, #24
	beq	2f
	clz	r7, r6
	lsr	r6, #24
	lsl	r6, r7
	bic	r6, #0x0080
	lsrs	r7, #1
	orrcs	r6, #0x0080
	orr	r6, r6, r7, lsl #12
	orr	r6, #0x4000
	b	2f
1:	add     r7, r3
	ldrh	ip, [r7, #2]
ARM_BE8(rev16	ip, ip)
	tst	ip, #0x4000
	and	ip, #0x8f00
	orrne	ip, r6	@ mask in offset bits 31-24
	orreq	ip, r0	@ mask in offset bits 7-0
ARM_BE8(rev16	ip, ip)
	strh	ip, [r7, #2]
	bne	2f
	ldrh	ip, [r7]
ARM_BE8(rev16	ip, ip)
	bic	ip, #0x20
	orr	ip, ip, r0, lsr #16
ARM_BE8(rev16	ip, ip)
	strh	ip, [r7]
2:	cmp	r4, r5
	ldrcc	r7, [r4], #4	@ use branch for delay slot
	bcc	1b
	bx	lr
#else
*/



/*
	ldr	r0, [r6, #HIGH_OFFSET]	@ pv_offset high word	//  r6의 상위 4바이트를 r0 에 저장
								// 0xFFFFFFFF
	ldr	r6, [r6, #LOW_OFFSET]	@ pv_offset low word	// r6의 하위 4바이트를 r6에 저장
								// 0x??000000
*/
#ifdef CONFIG_CPU_ENDIAN_BE8	// 22bit를 set 할경우 mov명령어 에서 -> mvn명령어로  명령어 변환이 됨!
							    // mov op code : 1101, mvn op code : 1111, 따라서 22bit만 set 할 경우 명령어가 변환이 됨. 
	moveq	r0, #0x00004000	@ set bit 22, mov to mvn instruction
#else
	// Z 플래그가 섰으니까, eq이다. 
	moveq	r0, #0x400000	@ set bit 22, mov to mvn instruction
#endif
	b	2f
1:	ldr	ip, [r7, r3]				// r7 즉, instruction의 주소를 delta offset 으로 보정해서 ip 에 넣어줌.
									// 이유 : 실시간으로 주소 변환을 하기 위해서 명령어의 immediate 값과 rotate 값을 변경.
	/* 2015. 12. 12. (토) 20:48:09 KST
	 * end driving 
	 * DH kim
	 */
#ifdef CONFIG_CPU_ENDIAN_BE8
	@ in BE8, we load data in BE, but instructions still in LE
	bic	ip, ip, #0xff000000
	tst	ip, #0x000f0000	@ check the rotation field
	orrne	ip, ip, r6, lsl #24 @ mask in offset bits 31-24
	biceq	ip, ip, #0x00004000 @ clear bit 22
	orreq	ip, ip, r0      @ mask in offset bits 7-0
#else
	bic	ip, ip, #0x000000ff								// 0x000000ff의 bitwise not을 한거랑 ip랑 AND연산 해서 ip에 저장,
														// 즉, ip의 하위 8비트(immediate)를 클리어 해준겁니다.
	tst	ip, #0xf00	@ check the rotation field			// 0xf00 = 0x00000f00, rotation field 가 0이면, imedi 필드만 계산하면되지.
	orrne	ip, ip, r6	@ mask in offset bits 31-24		// 64 bit operation. ref) arm/include/memory.h => __virt_to_phys()
														// set immediate value to delta (rotation field 가 0이 아닐때 들어옴.)
	biceq	ip, ip, #0x400000	@ clear bit 22			// 상위 32bit를 처리 할 때만, 764~765 라인을 실행함 (이때는 rotate field 0)
	orreq	ip, ip, r0	@ mask in offset bits 7-0		// rotate field 가 0 인 이유 상위 32bit만 가지고 처리를 하므로, 
#endif
	str	ip, [r7, r3]
/*
1:	.long	.						// r3		 
	.long	__pv_table_begin		// r4
	.long	__pv_table_end			// r5
2:	.long	__pv_phys_pfn_offset	// r6
	.long	__pv_offset				// r7
*/
2:	cmp	r4, r5
	ldrcc	r7, [r4], #4	@ use branch for delay slot
							/* -- arch/arm/kernel/vmlinux.lds.S
							.init.pv_table : {
								__pv_table_begin = .;	// r4
								*(.pv_table)			// r4 + 4
								__pv_table_end = .;		// r4 + 8
							}
							*/
							// r7에 결국 pv_table의 시작 포인터 값이 들어가 있음
	bcc	1b
	ret	lr
#endif
ENDPROC(__fixup_a_pv_table)

	.align
3:	.long __pv_offset

ENTRY(fixup_pv_table)
	stmfd	sp!, {r4 - r7, lr}
	mov	r3, #0			@ no offset
	mov	r4, r0			@ r0 = table start
	add	r5, r0, r1		@ r1 = table size
	bl	__fixup_a_pv_table
	ldmfd	sp!, {r4 - r7, pc}
ENDPROC(fixup_pv_table)

	.data
	.globl	__pv_phys_pfn_offset
	.type	__pv_phys_pfn_offset, %object
__pv_phys_pfn_offset:
	.word	0
	.size	__pv_phys_pfn_offset, . -__pv_phys_pfn_offset

	.globl	__pv_offset
	.type	__pv_offset, %object
__pv_offset:
	.quad	0
	.size	__pv_offset, . -__pv_offset
#endif

#include "head-common.S"
