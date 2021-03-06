/*
 *  linux/arch/arm/kernel/head-common.S
 *
 *  Copyright (C) 1994-2002 Russell King
 *  Copyright (c) 2003 ARM Limited
 *  All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#include <asm/assembler.h>

#define ATAG_CORE 0x54410001
#define ATAG_CORE_SIZE ((2*4 + 3*4) >> 2)
#define ATAG_CORE_SIZE_EMPTY ((2*4) >> 2)

#ifdef CONFIG_CPU_BIG_ENDIAN
#define OF_DT_MAGIC 0xd00dfeed
#else
#define OF_DT_MAGIC 0xedfe0dd0 /* 0xd00dfeed in big-endian */
#endif

/*
 * Exception handling.  Something went wrong and we can't proceed.  We
 * ought to tell the user, but since we don't have any guarantee that
 * we're even running on the right architecture, we do virtually nothing.
 *
 * If CONFIG_DEBUG_LL is set we try to print out something about the error
 * and hope for the best (useful if bootloader fails to pass a proper
 * machine ID for example).
 */
	__HEAD

/* Determine validity of the r2 atags pointer.  The heuristic requires
 * that the pointer be aligned, in the first 16k of physical RAM and
 * that the ATAG_CORE marker is first and present.  If CONFIG_OF_FLATTREE
 * is selected, then it will also accept a dtb pointer.  Future revisions
 * of this function may be more lenient with the physical address and
 * may also be able to move the ATAGS block if necessary.
 *
 * Returns:
 *  r2 either valid atags pointer, valid dtb pointer, or zero
 *  r5, r6 corrupted
 */
__vet_atags:
	tst	r2, #0x3			@ aligned? // 4byte 단위 aligned
	bne	1f

	ldr	r5, [r2, #0]			// r5 = r2의 첫번째 주소(atag size)
#ifdef CONFIG_OF_FLATTREE
	ldr	r6, =OF_DT_MAGIC		@ is it a DTB?
	cmp	r5, r6
	beq	2f
#endif
	cmp	r5, #ATAG_CORE_SIZE		@ is first tag ATAG_CORE?
	cmpne	r5, #ATAG_CORE_SIZE_EMPTY
	bne	1f
		ldr	r5, [r2, #4]			// r5 = r2의 두번째 필드(atag tag)
	ldr	r6, =ATAG_CORE		
	cmp	r5, r6				// r5 r6 tag 비교
	bne	1f
	// 밑에 C언어 구조랑 동일 
	/*
	   if (atag->hdr.tag != ATAG_CORE ||               
	  	(atag->hdr.size != tag_size(tag_core) &&    	
	  		atag->hdr.size != 2))
		return 1;
	 */

2:	ret	lr				@ atag/dtb pointer is ok

1:	mov	r2, #0
	ret	lr
ENDPROC(__vet_atags)

/*
 * The following fragment of code is executed with the MMU on in MMU mode,
 * and uses absolute addresses; this is not position independent.
 *
 *  r0  = cp#15 control register
 *  r1  = machine ID
 *  r2  = atags/dtb pointer
 *  r9  = processor ID
 */
	__INIT // .init text 섹션이라고 알려주는 매크로.
__mmap_switched:
	adr	r3, __mmap_switched_data // mmap_switched data 를 r3 에 불러옴

	// r4 = __data_loc, r5 = __sdata, r6 = __bss_start, r7 = _end
	// fp register : Frame Pointer 레지스터 : (복귀 함수의 스택 포인터를 저장)
	// * data_loc = 빌드되었을 때 바이너리에서의 데이터 섹션의 주소 
	// * sdata = 메모리에 로드되었을 때 메모리의 주소
	// XIP Mode 란? : 메모리에 이미지를 올리지 않고도 NAND Flash(ROM) Memory에서 바로 부팅이 가능한 기능
	// 따라서, XIP 가 설정되어 있지 않다면, data_loc 과 sdata 가 같으므로, r4와 r5가 같게 된다.
	// 하지만, XIP 가 설정되어있다면 data_loc과 sdata가 다르고,
	// data_loc영역에 데이터 수정을 하지 못하므로 data_loc(롬에 있던 이미지)를
	// s_data(메모리에 로드되는 영역)에 복사 해 주어야 함.
	// 따라서, XIP Mode 가 설정되지 못하면다면 103 ~ 107라인을 실행하지 않음.
	// band 참조
	ldmia	r3!, {r4, r5, r6, r7}
	cmp	r4, r5				@ Copy data segment if needed
1:	cmpne	r5, r6
	ldrne	fp, [r4], #4 // fp = *(__data_loc+4), (__data_loc+4 영역의 값을 fp 에 저장)
	strne	fp, [r5], #4 // *(__sdata+4) = fp (fp 에 __sdata+4 영역의 값을)
	bne	1b

	// bss 영역 초기화 루틴
	mov	fp, #0				@ Clear BSS (and zero fp)
1:	cmp	r6, r7 // (bss_start - _end < 0) CarryClear == Lower / CarrySet == Higher or Same
	strcc	fp, [r6],#4 // bss_start영역에 0을 채워 넣음.
	bcc	1b //(bss_start == _end 이면 종료


// r4 = processor id,r5 = __machine arch type, r6 = atag pointer, r7 = cr_alignment or 0
// sp = init_thread_union + THREAD_START_SP 
 ARM(	ldmia	r3, {r4, r5, r6, r7, sp}) 
 THUMB(	ldmia	r3, {r4, r5, r6, r7}	)
 THUMB(	ldr	sp, [r3, #16]		)
	str	r9, [r4]			@ Save processor ID // processor id 를 저장(r4 주소에)
	str	r1, [r5]			@ Save machine type // machine을 저장(r5 주소에)
	str	r2, [r6]			@ Save atags pointer // atag_pointer를 저장(r6 주소에)
	cmp	r7, #0				// cr_alignment 체크
	strne	r0, [r7]			@ Save control register values // cr_alignment 가 체크 되있으면, 
										// control register value를 
										// r7에 저장
	b	start_kernel
ENDPROC(__mmap_switched)

	.align	2
	.type	__mmap_switched_data, %object
__mmap_switched_data:
	.long	__data_loc			@ r4
	.long	_sdata				@ r5
	.long	__bss_start			@ r6
	.long	_end				@ r7
	.long	processor_id			@ r4
	.long	__machine_arch_type		@ r5
	.long	__atags_pointer			@ r6
#ifdef CONFIG_CPU_CP15
	.long	cr_alignment			@ r7
#else
	.long	0				@ r7
#endif
	.long	init_thread_union + THREAD_START_SP @ sp
	.size	__mmap_switched_data, . - __mmap_switched_data

/*
 * This provides a C-API version of __lookup_processor_type
 */
ENTRY(lookup_processor_type)
	stmfd	sp!, {r4 - r6, r9, lr}
	mov	r9, r0
	bl	__lookup_processor_type
	mov	r0, r5
	ldmfd	sp!, {r4 - r6, r9, pc}
ENDPROC(lookup_processor_type)

	__FINIT
	.text

/*
 * Read processor ID register (CP#15, CR0), and look up in the linker-built
 * supported processor list.  Note that we can't use the absolute addresses
 * for the __proc_info lists since we aren't running with the MMU on
 * (and therefore, we are not in the correct address space).  We have to
 * calculate the offset.
 *
 *	r9 = cpuid
 * Returns:
 *	r3, r4, r6 corrupted
 *	r5 = proc_info pointer in physical address space
 *	r9 = cpuid (preserved)
 */
__lookup_processor_type:
	adr	r3, __lookup_processor_type_data	//r3 = processor type 정보의 주소	
	ldmia	r3, {r4 - r6}				
	//r3(physical start addr) r4(virtual start addr), r5(begin addr), r6(end addr)
	sub	r3, r3, r4			@ get offset between virt&phys
	add	r5, r5, r3			@ convert virt addresses to pysical address space
	add	r6, r6, r3			
1:	ldmia	r5, {r3, r4}			@ value, mask //r3(value) r4(mask)
	and	r4, r4, r9			@ mask wanted bits // r4 & r9(cpuid) 
	teq	r3, r4				
	beq	2f
	add	r5, r5, #PROC_INFO_SZ		@ sizeof(proc_info_list)
	cmp	r5, r6				
	blo	1b				// r5 - r6 < 0 ---> 1b
	mov	r5, #0				@ unknown processor
2:	ret	lr
ENDPROC(__lookup_processor_type)

/*
 * Look in <asm/procinfo.h> for information about the __proc_info structure.
 */
    /* <asm/procinfo.h>에서 가져옴
    /*
     * Note!  struct processor is always defined if we're
     * using MULTI_CPU, otherwise this entry is unused,
     * but still exists.
     *
     * NOTE! The following structure is defined by assembly
     * language, NOT C code.  For more information, check:
     *  arch/arm/mm/proc-*.S and arch/arm/kernel/head.S
     */
    /*
       struct proc_info_list {
       unsigned int		cpu_val;
       unsigned int		cpu_mask;
       unsigned long		__cpu_mm_mmu_flags;	
       unsigned long		__cpu_io_mmu_flags;	
       unsigned long		__cpu_flush;		
       const char		*arch_name;
       const char		*elf_name;
       unsigned int		elf_hwcap;
       const char		*cpu_name;
       struct processor	*proc;
       struct cpu_tlb_fns	*tlb;
       struct cpu_user_fns	*user;
       struct cpu_cache_fns	*cache;
       };
     */
	.align	2
	.type	__lookup_processor_type_data, %object
__lookup_processor_type_data:
	.long	.			// '.'은 가상주소
	.long	__proc_info_begin 	// proc_info_list section 시작
	.long	__proc_info_end		// proc_info_list section 끝
	.size	__lookup_processor_type_data, . - __lookup_processor_type_data 
	//size = 현재주소 - __lookup_processor_type_data 

__error_lpae:
#ifdef CONFIG_DEBUG_LL
	adr	r0, str_lpae
	bl 	printascii
	b	__error
str_lpae: .asciz "\nError: Kernel with LPAE support, but CPU does not support LPAE.\n"
#else
	b	__error
#endif
	.align
ENDPROC(__error_lpae)

__error_p:
#ifdef CONFIG_DEBUG_LL
	adr	r0, str_p1
	bl	printascii
	mov	r0, r9
	bl	printhex8
	adr	r0, str_p2
	bl	printascii
	b	__error
str_p1:	.asciz	"\nError: unrecognized/unsupported processor variant (0x"
str_p2:	.asciz	").\n"
	.align
#endif
ENDPROC(__error_p)

__error:
#ifdef CONFIG_ARCH_RPC
/*
 * Turn the screen red on a error - RiscPC only.
 */
	mov	r0, #0x02000000
	mov	r3, #0x11		// 00010001
	orr	r3, r3, r3, lsl #8	 
	orr	r3, r3, r3, lsl #16
	str	r3, [r0], #4
	str	r3, [r0], #4
	str	r3, [r0], #4
	str	r3, [r0], #4
#endif
1:	mov	r0, r0
	b	1b
ENDPROC(__error)
