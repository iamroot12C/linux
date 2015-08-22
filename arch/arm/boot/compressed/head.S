/* Date : 2015. 07. 11. (Sat) 19:04:34 KST
   Source Driving presenter : DaeHee Kim
   Driving count : 001.

   Start Driving ...
*/
/* 꿀팁*/
// 1. #에다가 커서를 놓고  shift+5 누르면 해당 분기문을 이동하며 다님, 블록 알기에 좋음
// 2. :r!date 엔터하면 현재 커서에 지금날짜 자동입력.!!
// 3. 라인 옆에서 m(등록할 키, 예: ma) 명령어로 등록 후,'(등록한 키, 예: 'a) 입력하면 바로 이동할 수 있음



/*
 *  linux/arch/arm/boot/compressed/head.S
 *
 *  Copyright (C) 1996-2002 Russell King
 *  Copyright (C) 2004 Hyok S. Choi (MPU support)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/linkage.h>
#include <asm/assembler.h>
#include <asm/v7m.h>

 AR_CLASS(	.arch	armv7-a	)
 M_CLASS(	.arch	armv7-m	) // 이 정보를 참고해서 어셈블러가 번역을 함
		 		  // ARM 어셈블러를 위한 지시어.
				  // 어셈블러에게 이렇게 해라라고 지시하는 거
				  // 32비트 기준 2015.07.11기준 최신 버젼


/*
 * Debugging stuff
 *
 * Note that these macros must not contain any code which is not
 * 100% relocatable.  Any attempt to do so will result in a crash.
 * Please select one of the following when turning on debugging.
 */
#ifdef DEBUG 	// DEBUG가 디파인 되있으면 진입
		// 예, 빌드옵션에서 디버그를 설정해 주던지 등


#if defined(CONFIG_DEBUG_ICEDCC) // 또 얘가 설정되있으면 쭉쭉 진행
				 //If you define CP14 debug coprocessor, use the following macro definitions. 
				 // arm/ 디렉토리에서 $ make ARCH=arm menuconfig해서 화면 나오면, 커널 디버깅 해제하고 메이크하면
				 // 여기부분 통과하는 새로운 커널이 완성! 
				 // 여기서 menuconfig 한 내용은 kconfig파일의 내용을 이용해서 화면에 뿌려주고
				 // menuconfig에서 커널 디버깅 해제하고 저장하면 커널소스윗단의 .config파일에 저장되어 새로운 커널이 완성!
				 // 그리고 kconfig파일은 지금 이 파일의 부모디렉터리에 있습니다.



#if defined(CONFIG_CPU_V6) || defined(CONFIG_CPU_V6K) || defined(CONFIG_CPU_V7) // ARM버젼이 이럴 떄 진입
		.macro	loadsp, rb, tmp		// 이런게 여러게 정의되어있는데 상황에 맞게 정의될수 있다.
		.endm
		.macro	writeb, ch, rb		// 이렇게만 치면 아래 긴~ 명령어가 실행된다.
		mcr	p14, 0, \ch, c0, c5, 0	// 이렇게 길게쓰지말고 위의 라인처럼 간략히 써서 사용하자는 취지.
						// c0, c5 코 프로세서에서 쓰는 레지스터 같다.
		.endm
/*
   Date : 2015. 07. 11. (토) 21:24:34 KST
   Name : DaeHee Kim
   End Driving ... 
*/

/* Date : 2015. 07. 18. (토) 18:11:15 KST
   Source Driving presenter : Eunhwan Shin
   Driving count : 002.

   Start Driving ...
*/
#elif defined(CONFIG_CPU_XSCALE)	// xscale 타입의 ARM 일 때 진입
		.macro	loadsp, rb, tmp
		.endm
		.macro	writeb, ch, rb
		mcr	p14, 0, \ch, c8, c0, 0	// cp14 레지스터 c8(transmit 레지스터)의 내용을 ch에 저장 (디버그 관련 설정)
		.endm
#else	// 기타 타입일 때 진입
		.macro	loadsp, rb, tmp
		.endm
		.macro	writeb, ch, rb
		mcr	p14, 0, \ch, c1, c0, 0
		.endm
#endif

#else	// 디버그(CONFIG_DEBUG_ICEDCC)가 정의 안되어 있을 때 진입 (uart 사용 시)

#include CONFIG_DEBUG_LL_INCLUDE

		.macro	writeb,	ch, rb
		senduart \ch, \rb	// uart로 한 char 전송 (../include/debug/ 매크로 참고)
		.endm

#if defined(CONFIG_ARCH_SA1100)
		.macro	loadsp, rb, tmp
		mov	\rb, #0x80000000	@ physical base address	// SA1100 아키텍처 사용 시 uart base address 지정
#ifdef CONFIG_DEBUG_LL_SER3
		add	\rb, \rb, #0x00050000	@ Ser3	// 시리얼 3번 채널 사용 시 uart base address 지정
#else
		add	\rb, \rb, #0x00010000	@ Ser1	// 시리얼 1번 채널 사용 시 uart base address 지정
#endif
		.endm
#else
		.macro	loadsp,	rb, tmp
		addruart \rb, \tmp	// 내부적으로 MMU 활성화 여부에 따라 address 처리, 시리얼 관련 테스트 (../include/debug/sa1100.S)
		.endm
#endif
#endif
#endif	// 42 라인 DEBUG end
		.macro  kputc,val	// kputc 매그로 정의 (인자 val)
		mov	r0, \val	// val을 r0에 저장
		bl	putc		// putc로 분기 -> 1136라인
		.endm

		.macro	kphex,val,len
		mov	r0, \val
		mov	r1, #\len	// 인자를 r0, r1에 저장
		bl	phex		// phex로 분기
		.endm

		.macro	debug_reloc_start
#ifdef DEBUG
		kputc	#'\n'		// '\n' 출력
		kphex	r6, 8		/* processor id */
		kputc	#':'		// ':' 출력
		kphex	r7, 8		/* architecture id */
#ifdef CONFIG_CPU_CP15
		kputc	#':'
		mrc	p15, 0, r0, c1, c0	// p15의 값을 읽음
		kphex	r0, 8		/* control reg */
#endif
		kputc	#'\n'
		kphex	r5, 8		/* decompressed kernel start */	// kernel 압축 해제된 시작 주소 출력
		kputc	#'-'
		kphex	r9, 8		/* decompressed kernel end  */	// 마지막 주소 출력
		kputc	#'>'
		kphex	r4, 8		/* kernel execution address */	// kernel 실행 주소 출력
		kputc	#'\n'
#endif
		.endm

		.macro	debug_reloc_end
#ifdef DEBUG
		kphex	r5, 8		/* end of kernel */	// kernel의 마지막 주소 출력 ?
		kputc	#'\n'
		mov	r0, r4		// r4(kernel 실행 주소)의 값을 r0에 셋팅
		bl	memdump		/* dump 256 bytes at start of kernel */
#endif
		.endm

		.section ".start", #alloc, #execinstr	// .start 섹션을 정의 (#alloc;할당 가능한, #execinstr:실행 가능한)
/*
 * sort out different calling conventions
 */
		.align	// default 4 (2의 배수 단위)
		/*
		 * Always enter in ARM state for CPUs that support the ARM ISA.
		 * As of today (2014) that's exactly the members of the A and R
		 * classes.
		 */
 AR_CLASS(	.arm	)	// arm 명령어 셋을 사용함
start:
		.type	start,#function
		.rept	7	// .endr까지 7번 반복
		mov	r0, r0	// dummy instruction -> 부트 로더 주소 오류 방지를 위한 코드
		.endr
   ARM(		mov	r0, r0		)	// 1회 더 총 8번
   ARM(		b	1f		)	// 1f(forward)로 점프
/*
   Date : 2015. 07. 18. (토) 21:45:51 KST
   Name : Eunhwan Shin
   End Driving ... 
*/


/*
   Date : 2015. 07. 25. (토) 18:xx:xx KST
   Source Driving presenter : Hyeonjun Shin
   Driving count : 003.

   Start Driving ...
*/
 THUMB(		adr	r12, BSYM(1f)	)	//V5부터 Thumb / ARM 모드 지원. THUMB모드일때 이 명령어를 수행함. 상대주소값 BSYM(1f)를 R12에 저장함.
//BSYM - 주소를 1개 증가시켜주고(명령어 padding), 1f로 라벨을 저장함.
//BSYM매크로는 레이블 + 1(word) 한 주소를 나타냄. THUMB에서는 16bit, 2Byte.

 THUMB(		bx	r12		) //BX : ARM-THUMB 모드변환명령어, r12가 가리키는곳으로 jump
//bx로 점프하면 하단의 ARM_BE8(setend...) 로 감

		.word	_magic_sig	@ Magic numbers to help the loader
//로더가 불러들일때 엉뚱한 이미지가 올 수 있기때문에 일정한 넘버를 체크하여 일치하는 이미지를 판단하게끔 함.
//ELF의 헤더에서 매직넘버를 체크할 수 있다.
//LINUX KERNEL IMAGE임을 zimage를 읽은 뒤 확인함.
//magic number 정의는 vmlinux.lds.S에 있음.
//Line 68~70, ZIMAGE_MAGIC은 10에.
		.word	_magic_start	@ absolute load/run zImage address//
		.word	_magic_end	@ zImage end address
		.word	0x04030201	@ endianness flag

 THUMB(		.thumb			) //Assembly Directive로서 실행되지는 않음.
			//Assembler가 이후 코드를 THUMB으로 해석하도록 하는 지시어.
			//THUMB으로 진입했다면 이후 코드들도 전부 THUMB으로 실행함.
1:
 ARM_BE8(	setend	be		)	@ go BE8 if compiled for BE8
//BIG ENDIAN지원하는경우 big endian 모드로 동작하게 함.
//v7이 big endian을 지원함. 
//default 는 little endian.

 AR_CLASS(	mrs	r9, cpsr	) //CPSR값을 r9로 로드. mrs가 move to register from special register
//AR_CLASS는 arm v7a, v7a일때 실행.

#ifdef CONFIG_ARM_VIRT_EXT
//가상화기술에 관한 내용. ARM V7 ARCH가 지원함.
//커널이 가상화설정이 되어있으면 아래 실행.
		bl	__hyp_stub_install	@ get into SVC mode, reversibly
		
	// /arch/arm/kernel/hyp-stub.S 의 매크로를 통해 line 40의 store_primary_cpu_mode 매크로를 실행시킴.
#endif
		mov	r7, r1			@ save architecture ID
//r1의 데이터를 r7에 저장
		mov	r8, r2			@ save atags pointer
//r2의 데이터를 r8에 저장
//atag는 환경변수 설정을 가지고 있는 데이터 모음

//앞으로 r1과 r2가 사용될 것이므로 r7, r8 로 옮겨놓음.


#ifndef CONFIG_CPU_V7M 
		/*
		 * Booting from Angel - need to enter SVC mode and disable
		 * FIQs/IRQs (numeric definitions from angel arm.h source).
		 * We only do this if we were in user mode on entry.
		 */
		mrs	r2, cpsr		@ get current mode //CPSR값을 R2로 옮김
		tst	r2, #3			@ not user?	//user모드인지 검사해서
		bne	not_angel				//아니면 not_angel로 이동
		mov	r0, #0x17		@ angel_SWIreason_EnterSVC
 ARM(		swi	0x123456	)	@ angel_SWI_ARM // 0x17 매개변수를 r0에 넣고
								//0x123456 번 swi를 실행함.
 THUMB(		svc	0xab		)	@ angel_SWI_THUMB //thumb이면 0xab를 svc함?
not_angel:
		safe_svcmode_maskall r0		//r0를 매개변수로  safe_svcmode_maskall 수행.
// arch/arm/include/asm/assembler.h에 정의됨
// LINE 324.
						//svc모드를 수행함
						
		msr	spsr_cxsf, r9		@ Save the CPU boot mode in
						@ SPSR

//r9에 svc 모드 변경 전 cpu의 모드가 저장되어있음. 212라인 AR_CLASS, svc모드 진입전에 저장해놨음.

#endif
		/*
		 * Note that some cache flushing and other stuff may
		 * be needed here - is there an Angel SWI call for this?
		 */

		/*
		 * some architecture specific code can be inserted
		 * by the linker here, but it should preserve r7, r8, and r9.
		 */

//<<<<<<<<<<<<여기서부터 text영역이 시작>>>>>>>>>>>>>>
		.text

#ifdef CONFIG_AUTO_ZRELADDR
//압축된 zimage를 auto로 할거면 이쪽으로 진입.
//아니면 else로 진입함.
//makefile에 정의할 수 있음.

		/*
		 * Find the start of physical memory.  As we are executing
		 * without the MMU on, we are in the physical address space.
		 * We just need to get rid of any offset by aligning the
		 * address.
		 *
		 * This alignment is a balance between the requirements of
		 * different platforms - we have chosen 128MB to allow
		 * platforms which align the start of their physical memory
		 * to 128MB to use this feature, while allowing the zImage
		 * to be placed within the first 128MB of memory on other
		 * platforms.  Increasing the alignment means we place
		 * stricter alignment requirements on the start of physical
		 * memory, but relaxing it means that we break people who
		 * are already placing their zImage in (eg) the top 64MB
		 * of this range.
		 */
		//부트로더가 상위 128MB 공간에 기본적으로 ZIMAGE를 불러오기 때문에
		//이와 같은 연산을 수행함.

		mov	r4, pc		//다음 실행할 명령의 주소를 r4로 이동
		and	r4, r4, #0xf8000000	//pc값을 비교하여 메모리 주소 위치를 확인.
						//128MB의 배수 위치인지 확인.
						

		/* Determine final kernel image address. */
		add	r4, r4, #TEXT_OFFSET	//위에서 계산한 주소값(128MB의 배수)에 TEXT OFFSET을 더하여 R4에 저장
#else			//ZIMAGE를 AUTOLOAD할게 아니면
		ldr	r4, =zreladdr		//ZIMAGE LOCATION을 R4에 저장한다.
						//IMAGE를 임의의 위치로 재배치할때 사용할 수 있음.
	//zreladdr의 값은 board에 따라 다르다.
	//Makefile.boot에 zreladdr값이 정의되어있음.
#endif

		/*
		 * Set up a page table only if it won't overwrite ourself.
		 * That means r4 < pc || r4 - 16k page directory > &_end.
		 * Given that r4 > &_end is most unfrequent, we add a rough
		 * additional 1MB of room for a possible appended DTB.
		 */
//DTB는 커널 이미지 가장 끝에 1MB공간에 배치함.
//4000~8000번지까지 페이지테이블을 배치하는 공간.

		mov	r0, pc		//pc값을 r0로 이동
		cmp	r0, r4		//r0와 r4값을 비교 r0-r4 가 음수면 carry발생.
					//즉, r0 < r4일때 cc니모닉이 수행됨.
					//r4에 압축해제된 커널의 주소가 저장됨
					//r0의 pc값과 비교해서

					//만약에 pc값이 현 수행중인 커널위치보다 작으면
					//이상하니까 재배치!
					//부트로더의 버그를 대비해서 ???

		ldrcc	r0, LC0+32	//cc = carry clear carry flag가 0이면 수행.
					//LC0+32 한 값을 r0레지스터에 1워드 저장.

					//지금 코드의 현위치와 비교하여, 

		addcc	r0, r0, pc	// r0 = r0 + pc
		cmpcc	r4, r0		// relocation된 주소와 비교해서 r4가 작으면,
					// r4에 1비트를 set함.??
		orrcc	r4, r4, #1		@ remember we skipped cache on
					// 주소에 1비트를 set해서 나중에 cache 설정할지 안할지의 여부를 설정함.
		blcs	cache_on	//r4가 작으면, orrcc를 하고, 아니면 blcs로 이동


//여기까지

/*
   Date : 2015. 07. 25. (토) 21:36:52 KST

   Name : Hyeonjun Shin
   End Driving ... 
*/

restart:	adr	r0, LC0
		ldmia	r0, {r1, r2, r3, r6, r10, r11, r12}
		ldr	sp, [r0, #28]

		/*
		 * We might be running at a different address.  We need
		 * to fix up various pointers.
		 */
		sub	r0, r0, r1		@ calculate the delta offset
		add	r6, r6, r0		@ _edata
		add	r10, r10, r0		@ inflated kernel size location

		/*
		 * The kernel build system appends the size of the
		 * decompressed kernel at the end of the compressed data
		 * in little-endian form.
		 */
		ldrb	r9, [r10, #0]
		ldrb	lr, [r10, #1]
		orr	r9, r9, lr, lsl #8
		ldrb	lr, [r10, #2]
		ldrb	r10, [r10, #3]
		orr	r9, r9, lr, lsl #16
		orr	r9, r9, r10, lsl #24

#ifndef CONFIG_ZBOOT_ROM
		/* malloc space is above the relocated stack (64k max) */
		add	sp, sp, r0
		add	r10, sp, #0x10000
#else
		/*
		 * With ZBOOT_ROM the bss/stack is non relocatable,
		 * but someone could still run this code from RAM,
		 * in which case our reference is _edata.
		 */
		mov	r10, r6
#endif

		mov	r5, #0			@ init dtb size to 0
#ifdef CONFIG_ARM_APPENDED_DTB
/*
 *   r0  = delta
 *   r2  = BSS start
 *   r3  = BSS end
 *   r4  = final kernel address (possibly with LSB set)
 *   r5  = appended dtb size (still unknown)
 *   r6  = _edata
 *   r7  = architecture ID
 *   r8  = atags/device tree pointer
 *   r9  = size of decompressed image
 *   r10 = end of this image, including  bss/stack/malloc space if non XIP
 *   r11 = GOT start
 *   r12 = GOT end
 *   sp  = stack pointer
 *
 * if there are device trees (dtb) appended to zImage, advance r10 so that the
 * dtb data will get relocated along with the kernel if necessary.
 */

		ldr	lr, [r6, #0]
#ifndef __ARMEB__
		ldr	r1, =0xedfe0dd0		@ sig is 0xd00dfeed big endian
#else
		ldr	r1, =0xd00dfeed
#endif
		cmp	lr, r1
		bne	dtb_check_done		@ not found

#ifdef CONFIG_ARM_ATAG_DTB_COMPAT
		/*
		 * OK... Let's do some funky business here.
		 * If we do have a DTB appended to zImage, and we do have
		 * an ATAG list around, we want the later to be translated
		 * and folded into the former here. No GOT fixup has occurred
		 * yet, but none of the code we're about to call uses any
		 * global variable.
		*/

		/* Get the initial DTB size */
		ldr	r5, [r6, #4]
#ifndef __ARMEB__
		/* convert to little endian */
		eor	r1, r5, r5, ror #16
		bic	r1, r1, #0x00ff0000
		mov	r5, r5, ror #8
		eor	r5, r5, r1, lsr #8
#endif
		/* 50% DTB growth should be good enough */
		add	r5, r5, r5, lsr #1
		/* preserve 64-bit alignment */
		add	r5, r5, #7
		bic	r5, r5, #7
		/* clamp to 32KB min and 1MB max */
		cmp	r5, #(1 << 15)
		movlo	r5, #(1 << 15)
		cmp	r5, #(1 << 20)
		movhi	r5, #(1 << 20)
		/* temporarily relocate the stack past the DTB work space */
		add	sp, sp, r5

		stmfd	sp!, {r0-r3, ip, lr}
		mov	r0, r8
		mov	r1, r6
		mov	r2, r5
		bl	atags_to_fdt

		/*
		 * If returned value is 1, there is no ATAG at the location
		 * pointed by r8.  Try the typical 0x100 offset from start
		 * of RAM and hope for the best.
		 */
		cmp	r0, #1
		sub	r0, r4, #TEXT_OFFSET
		bic	r0, r0, #1
		add	r0, r0, #0x100
		mov	r1, r6
		mov	r2, r5
		bleq	atags_to_fdt

		ldmfd	sp!, {r0-r3, ip, lr}
		sub	sp, sp, r5
#endif

		mov	r8, r6			@ use the appended device tree

		/*
		 * Make sure that the DTB doesn't end up in the final
		 * kernel's .bss area. To do so, we adjust the decompressed
		 * kernel size to compensate if that .bss size is larger
		 * than the relocated code.
		 */
		ldr	r5, =_kernel_bss_size
		adr	r1, wont_overwrite
		sub	r1, r6, r1
		subs	r1, r5, r1
		addhi	r9, r9, r1

		/* Get the current DTB size */
		ldr	r5, [r6, #4]
#ifndef __ARMEB__
		/* convert r5 (dtb size) to little endian */
		eor	r1, r5, r5, ror #16
		bic	r1, r1, #0x00ff0000
		mov	r5, r5, ror #8
		eor	r5, r5, r1, lsr #8
#endif

		/* preserve 64-bit alignment */
		add	r5, r5, #7
		bic	r5, r5, #7

		/* relocate some pointers past the appended dtb */
		add	r6, r6, r5
		add	r10, r10, r5
		add	sp, sp, r5
dtb_check_done:
#endif

/*
 * Check to see if we will overwrite ourselves.
 *   r4  = final kernel address (possibly with LSB set)
 *   r9  = size of decompressed image
 *   r10 = end of this image, including  bss/stack/malloc space if non XIP
 * We basically want:
 *   r4 - 16k page directory >= r10 -> OK
 *   r4 + image length <= address of wont_overwrite -> OK
 * Note: the possible LSB in r4 is harmless here.
 */
		add	r10, r10, #16384
		cmp	r4, r10
		bhs	wont_overwrite
		add	r10, r4, r9
		adr	r9, wont_overwrite
		cmp	r10, r9
		bls	wont_overwrite

/*
 * Relocate ourselves past the end of the decompressed kernel.
 *   r6  = _edata
 *   r10 = end of the decompressed kernel
 * Because we always copy ahead, we need to do it from the end and go
 * backward in case the source and destination overlap.
 */
		/*
		 * Bump to the next 256-byte boundary with the size of
		 * the relocation code added. This avoids overwriting
		 * ourself when the offset is small.
		 */
		add	r10, r10, #((reloc_code_end - restart + 256) & ~255)
		bic	r10, r10, #255

		/* Get start of code we want to copy and align it down. */
		adr	r5, restart
		bic	r5, r5, #31

/* Relocate the hyp vector base if necessary */
#ifdef CONFIG_ARM_VIRT_EXT
		mrs	r0, spsr
		and	r0, r0, #MODE_MASK
		cmp	r0, #HYP_MODE
		bne	1f

		bl	__hyp_get_vectors
		sub	r0, r0, r5
		add	r0, r0, r10
		bl	__hyp_set_vectors
1:
#endif

		sub	r9, r6, r5		@ size to copy
		add	r9, r9, #31		@ rounded up to a multiple
		bic	r9, r9, #31		@ ... of 32 bytes
		add	r6, r9, r5
		add	r9, r9, r10

1:		ldmdb	r6!, {r0 - r3, r10 - r12, lr}
		cmp	r6, r5
		stmdb	r9!, {r0 - r3, r10 - r12, lr}
		bhi	1b

		/* Preserve offset to relocated code. */
		sub	r6, r9, r6

#ifndef CONFIG_ZBOOT_ROM
		/* cache_clean_flush may use the stack, so relocate it */
		add	sp, sp, r6
#endif

		bl	cache_clean_flush

		adr	r0, BSYM(restart)
		add	r0, r0, r6
		mov	pc, r0

wont_overwrite:
/*
 * If delta is zero, we are running at the address we were linked at.
 *   r0  = delta
 *   r2  = BSS start
 *   r3  = BSS end
 *   r4  = kernel execution address (possibly with LSB set)
 *   r5  = appended dtb size (0 if not present)
 *   r7  = architecture ID
 *   r8  = atags pointer
 *   r11 = GOT start
 *   r12 = GOT end
 *   sp  = stack pointer
 */
		orrs	r1, r0, r5
		beq	not_relocated

		add	r11, r11, r0
		add	r12, r12, r0

#ifndef CONFIG_ZBOOT_ROM
		/*
		 * If we're running fully PIC === CONFIG_ZBOOT_ROM = n,
		 * we need to fix up pointers into the BSS region.
		 * Note that the stack pointer has already been fixed up.
		 */
		add	r2, r2, r0
		add	r3, r3, r0

		/*
		 * Relocate all entries in the GOT table.
		 * Bump bss entries to _edata + dtb size
		 */
1:		ldr	r1, [r11, #0]		@ relocate entries in the GOT
		add	r1, r1, r0		@ This fixes up C references
		cmp	r1, r2			@ if entry >= bss_start &&
		cmphs	r3, r1			@       bss_end > entry
		addhi	r1, r1, r5		@    entry += dtb size
		str	r1, [r11], #4		@ next entry
		cmp	r11, r12
		blo	1b

		/* bump our bss pointers too */
		add	r2, r2, r5
		add	r3, r3, r5

#else

		/*
		 * Relocate entries in the GOT table.  We only relocate
		 * the entries that are outside the (relocated) BSS region.
		 */
1:		ldr	r1, [r11, #0]		@ relocate entries in the GOT
		cmp	r1, r2			@ entry < bss_start ||
		cmphs	r3, r1			@ _end < entry
		addlo	r1, r1, r0		@ table.  This fixes up the
		str	r1, [r11], #4		@ C references.
		cmp	r11, r12
		blo	1b
#endif

not_relocated:	mov	r0, #0
1:		str	r0, [r2], #4		@ clear bss
		str	r0, [r2], #4
		str	r0, [r2], #4
		str	r0, [r2], #4
		cmp	r2, r3
		blo	1b

		/*
		 * Did we skip the cache setup earlier?
		 * That is indicated by the LSB in r4.
		 * Do it now if so.
		 */
		tst	r4, #1
		bic	r4, r4, #1
		blne	cache_on

/*
 * The C runtime environment should now be setup sufficiently.
 * Set up some pointers, and start decompressing.
 *   r4  = kernel execution address
 *   r7  = architecture ID
 *   r8  = atags pointer
 */
		mov	r0, r4
		mov	r1, sp			@ malloc space above stack
		add	r2, sp, #0x10000	@ 64k max
		mov	r3, r7
		bl	decompress_kernel
		bl	cache_clean_flush
		bl	cache_off
		mov	r1, r7			@ restore architecture number
		mov	r2, r8			@ restore atags pointer

#ifdef CONFIG_ARM_VIRT_EXT
		mrs	r0, spsr		@ Get saved CPU boot mode
		and	r0, r0, #MODE_MASK
		cmp	r0, #HYP_MODE		@ if not booted in HYP mode...
		bne	__enter_kernel		@ boot kernel directly

		adr	r12, .L__hyp_reentry_vectors_offset
		ldr	r0, [r12]
		add	r0, r0, r12

		bl	__hyp_set_vectors
		__HVC(0)			@ otherwise bounce to hyp mode

		b	.			@ should never be reached

		.align	2
.L__hyp_reentry_vectors_offset:	.long	__hyp_reentry_vectors - .
#else
		b	__enter_kernel
#endif

		.align	2
		.type	LC0, #object
LC0:		.word	LC0			@ r1
		.word	__bss_start		@ r2
		.word	_end			@ r3
		.word	_edata			@ r6
		.word	input_data_end - 4	@ r10 (inflated size location)
		.word	_got_start		@ r11
		.word	_got_end		@ ip
		.word	.L_user_stack_end	@ sp
		.word	_end - restart + 16384 + 1024*1024
		.size	LC0, . - LC0

#ifdef CONFIG_ARCH_RPC
		.globl	params
params:		ldr	r0, =0x10000100		@ params_phys for RPC
		mov	pc, lr
		.ltorg
		.align
#endif

/*
 * Turn on the cache.  We need to setup some page tables so that we
 * can have both the I and D caches on.
 *
 * We place the page tables 16k down from the kernel execution address,
 * and we hope that nothing else is using it.  If we're using it, we
 * will go pop!
 *
 * On entry,
 *  r4 = kernel execution address
 *  r7 = architecture number
 *  r8 = atags pointer
 * On exit,
 *  r0, r1, r2, r3, r9, r10, r12 corrupted
 * This routine must preserve:
 *  r4, r7, r8
 */
		.align	5 // instruction cache = 2^5 = 32Byte로 정렬.
cache_on:	mov	r3, #8			@ cache_on function
					//8을 r3에 저장한 뒤
		b	call_cache_fn	//이동
					//

/*
 * Initialize the highest priority protection region, PR7
 * to cover all 32bit address and cacheable and bufferable.
 */
__armv4_mpu_cache_on:
		mov	r0, #0x3f		@ 4G, the whole
		mcr	p15, 0, r0, c6, c7, 0	@ PR7 Area Setting
		mcr 	p15, 0, r0, c6, c7, 1

		mov	r0, #0x80		@ PR7
		mcr	p15, 0, r0, c2, c0, 0	@ D-cache on
		mcr	p15, 0, r0, c2, c0, 1	@ I-cache on
		mcr	p15, 0, r0, c3, c0, 0	@ write-buffer on

		mov	r0, #0xc000
		mcr	p15, 0, r0, c5, c0, 1	@ I-access permission
		mcr	p15, 0, r0, c5, c0, 0	@ D-access permission

		mov	r0, #0
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		mcr	p15, 0, r0, c7, c5, 0	@ flush(inval) I-Cache
		mcr	p15, 0, r0, c7, c6, 0	@ flush(inval) D-Cache
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
						@ ...I .... ..D. WC.M
		orr	r0, r0, #0x002d		@ .... .... ..1. 11.1
		orr	r0, r0, #0x1000		@ ...1 .... .... ....

		mcr	p15, 0, r0, c1, c0, 0	@ write control reg

		mov	r0, #0
		mcr	p15, 0, r0, c7, c5, 0	@ flush(inval) I-Cache
		mcr	p15, 0, r0, c7, c6, 0	@ flush(inval) D-Cache
		mov	pc, lr

__armv3_mpu_cache_on:
		mov	r0, #0x3f		@ 4G, the whole
		mcr	p15, 0, r0, c6, c7, 0	@ PR7 Area Setting

		mov	r0, #0x80		@ PR7
		mcr	p15, 0, r0, c2, c0, 0	@ cache on
		mcr	p15, 0, r0, c3, c0, 0	@ write-buffer on

		mov	r0, #0xc000
		mcr	p15, 0, r0, c5, c0, 0	@ access permission

		mov	r0, #0
		mcr	p15, 0, r0, c7, c0, 0	@ invalidate whole cache v3
		/*
		 * ?? ARMv3 MMU does not allow reading the control register,
		 * does this really work on ARMv3 MPU?
		 */
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
						@ .... .... .... WC.M
		orr	r0, r0, #0x000d		@ .... .... .... 11.1
		/* ?? this overwrites the value constructed above? */
		mov	r0, #0
		mcr	p15, 0, r0, c1, c0, 0	@ write control reg

		/* ?? invalidate for the second time? */
		mcr	p15, 0, r0, c7, c0, 0	@ invalidate whole cache v3
		mov	pc, lr

#ifdef CONFIG_CPU_DCACHE_WRITETHROUGH
#define CB_BITS 0x08
#else
#define CB_BITS 0x0c
#endif

__setup_mmu:	sub	r3, r4, #16384		@ Page directory size 16KB임.
		bic	r3, r3, #0xff		@ Align the pointer, 8비트를 마스킹해서
		bic	r3, r3, #0x3f00		//뒤의 8비트를 0으로 클리어, 32KB의 윗쪽 어드레스만 남음.
//r3에는 relocation된 start번지가 저장된다.

//	0xff   = 1111 1111
//	0x3f00 = 1111 1100 0000 0000
//	


/*
 * Initialise the page tables, turning on the cacheable and bufferable
 * bits for the RAM area only.
 */
		mov	r0, r3			//r0 = r3 코드 시작된 지점을 r0로.
		mov	r9, r0, lsr #18		//18비트씩 R0를 Shift Right해서 R9로.
		mov	r9, r9, lsl #18		//R9을 Shift Left 18비트 하여 R9로.
						//앞의 14비트가 남는다.
						//@ start of RAM, Physical Base Address의 윗쪽단이 커널 코드가 올라간 메모리 영역.
						//R9에는 256KB 번지째 숫자가 남음.

		add	r10, r9, #0x10000000	@ a reasonable RAM size
						//천만번지(256MB)를 R9에 더해서 R10으로.

/*						//8000번지 위에 있는 페이지테이블을 생성하는중..
=========================== 
2015. 07. 25. (토) 21:35:30 KST
===========================
*/
		mov	r1, #0x12		@ XN|U + section mapping
		orr	r1, r1, #3 << 10	@ AP=11
		add	r2, r3, #16384
1:		cmp	r1, r9			@ if virt > start of RAM
		cmphs	r10, r1			@   && end of RAM > virt
		bic	r1, r1, #0x1c		@ clear XN|U + C + B
		orrlo	r1, r1, #0x10		@ Set XN|U for non-RAM
		orrhs	r1, r1, r6		@ set RAM section settings
		str	r1, [r0], #4		@ 1:1 mapping
		add	r1, r1, #1048576
		teq	r0, r2
		bne	1b
/*
 * If ever we are running from Flash, then we surely want the cache
 * to be enabled also for our execution instance...  We map 2MB of it
 * so there is no map overlap problem for up to 1 MB compressed kernel.
 * If the execution is in RAM then we would only be duplicating the above.
 */
		orr	r1, r6, #0x04		@ ensure B is set for this
		orr	r1, r1, #3 << 10
		mov	r2, pc
		mov	r2, r2, lsr #20
		orr	r1, r1, r2, lsl #20
		add	r0, r3, r2, lsl #2
		str	r1, [r0], #4
		add	r1, r1, #1048576
		str	r1, [r0]
		mov	pc, lr
ENDPROC(__setup_mmu)

@ Enable unaligned access on v6, to allow better code generation
@ for the decompressor C code:
__armv6_mmu_cache_on:
		mrc	p15, 0, r0, c1, c0, 0	@ read SCTLR
		bic	r0, r0, #2		@ A (no unaligned access fault)
		orr	r0, r0, #1 << 22	@ U (v6 unaligned access model)
		mcr	p15, 0, r0, c1, c0, 0	@ write SCTLR
		b	__armv4_mmu_cache_on

__arm926ejs_mmu_cache_on:
#ifdef CONFIG_CPU_DCACHE_WRITETHROUGH
		mov	r0, #4			@ put dcache in WT mode
		mcr	p15, 7, r0, c15, c0, 0
#endif

__armv4_mmu_cache_on:
		mov	r12, lr
#ifdef CONFIG_MMU
		mov	r6, #CB_BITS | 0x12	@ U
		bl	__setup_mmu
		mov	r0, #0
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		mcr	p15, 0, r0, c8, c7, 0	@ flush I,D TLBs
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
		orr	r0, r0, #0x5000		@ I-cache enable, RR cache replacement
		orr	r0, r0, #0x0030
 ARM_BE8(	orr	r0, r0, #1 << 25 )	@ big-endian page tables
		bl	__common_mmu_cache_on
		mov	r0, #0
		mcr	p15, 0, r0, c8, c7, 0	@ flush I,D TLBs
#endif
		mov	pc, r12

__armv7_mmu_cache_on:
		mov	r12, lr		//링크레지스터값을 r12에 이동.
#ifdef CONFIG_MMU			//MMU가 설정되어있다면
		mrc	p15, 0, r11, c0, c1, 4	@ read ID_MMFR0 -> r11로 저장
		tst	r11, #0xf		@ VMSA	Virtual Memory System Architecture
						//이 다 되었는가 확인하고
		movne	r6, #CB_BITS | 0x02	@ !XN	//설정이 안되어있으면 캐시와 버퍼비트를 0x02와  OR해서 r6에 잡아놓은 다음에

		blne	__setup_mmu		//MMU 설정하게끔 이동.
		mov	r0, #0
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		tst	r11, #0xf		@ VMSA
		mcrne	p15, 0, r0, c8, c7, 0	@ flush I,D TLBs
#endif
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
		bic	r0, r0, #1 << 28	@ clear SCTLR.TRE
		orr	r0, r0, #0x5000		@ I-cache enable, RR cache replacement
		orr	r0, r0, #0x003c		@ write buffer
		bic	r0, r0, #2		@ A (no unaligned access fault)
		orr	r0, r0, #1 << 22	@ U (v6 unaligned access model)
						@ (needed for ARM1176)
#ifdef CONFIG_MMU
 ARM_BE8(	orr	r0, r0, #1 << 25 )	@ big-endian page tables
		mrcne   p15, 0, r6, c2, c0, 2   @ read ttb control reg
		orrne	r0, r0, #1		@ MMU enabled
		movne	r1, #0xfffffffd		@ domain 0 = client
		bic     r6, r6, #1 << 31        @ 32-bit translation system
		bic     r6, r6, #3 << 0         @ use only ttbr0
		mcrne	p15, 0, r3, c2, c0, 0	@ load page table pointer
		mcrne	p15, 0, r1, c3, c0, 0	@ load domain access control
		mcrne   p15, 0, r6, c2, c0, 2   @ load ttb control
#endif
		mcr	p15, 0, r0, c7, c5, 4	@ ISB
		mcr	p15, 0, r0, c1, c0, 0	@ load control register
		mrc	p15, 0, r0, c1, c0, 0	@ and read it back
		mov	r0, #0
		mcr	p15, 0, r0, c7, c5, 4	@ ISB
		mov	pc, r12

__fa526_cache_on:
		mov	r12, lr
		mov	r6, #CB_BITS | 0x12	@ U
		bl	__setup_mmu
		mov	r0, #0
		mcr	p15, 0, r0, c7, c7, 0	@ Invalidate whole cache
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		mcr	p15, 0, r0, c8, c7, 0	@ flush UTLB
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
		orr	r0, r0, #0x1000		@ I-cache enable
		bl	__common_mmu_cache_on
		mov	r0, #0
		mcr	p15, 0, r0, c8, c7, 0	@ flush UTLB
		mov	pc, r12

__common_mmu_cache_on:
#ifndef CONFIG_THUMB2_KERNEL
#ifndef DEBUG
		orr	r0, r0, #0x000d		@ Write buffer, mmu
#endif
		mov	r1, #-1
		mcr	p15, 0, r3, c2, c0, 0	@ load page table pointer
		mcr	p15, 0, r1, c3, c0, 0	@ load domain access control
		b	1f
		.align	5			@ cache line aligned
1:		mcr	p15, 0, r0, c1, c0, 0	@ load control register
		mrc	p15, 0, r0, c1, c0, 0	@ and read it back to
		sub	pc, lr, r0, lsr #32	@ properly flush pipeline
#endif

#define PROC_ENTRY_SIZE (4*5)

/*
 * Here follow the relocatable cache support functions for the
 * various processors.  This is a generic hook for locating an
 * entry and jumping to an instruction at the specified offset
 * from the start of the block.  Please note this is all position
 * independent code.
 *
 *  r1  = corrupted
 *  r2  = corrupted
 *  r3  = block offset
 *  r9  = corrupted
 *  r12 = corrupted
 */

call_cache_fn:	adr	r12, proc_types  //proc_types 의 주소를 r12에 저장한 후
#ifdef CONFIG_CPU_CP15	//CP15가 설정되어있으면
		mrc	p15, 0, r9, c0, c0	@ get processor ID
			//R9에 MPIDR 레지스터에 있는 값을 저장한다.

#elif defined(CONFIG_CPU_V7M)//만약 V7M이 정의되어있다면
		/*
		 * On v7-M the processor id is located in the V7M_SCB_CPUID
		 * register, but as cache handling is IMPLEMENTATION DEFINED on
		 * v7-M (if existant at all) we just return early here.
		 * If V7M_SCB_CPUID were used the cpu ID functions (i.e.
		 * __armv7_mmu_cache_{on,off,flush}) would be selected which
		 * use cp15 registers that are not implemented on v7-M.
		 */
		bx	lr //원래대로 복귀한다.
#else//V7 아키텍터가 아니면
		ldr	r9, =CONFIG_PROCESSOR_ID //프로세서ID를 R9에 저장한다.
#endif
1:		ldr	r1, [r12, #0]		@ get value //R12 + 0번지의 값을 r1에 저장
		ldr	r2, [r12, #4]		@ get mask  //R12 + 4번지의 값을 r2에 저장
		eor	r1, r1, r9		@ (real ^ match) //r1과 r9의 값이 같은지 판별해서
		tst	r1, r2			@       & mask   //r1 r2 마스크값 비교
 ARM(		addeq	pc, r12, r3		) @ call cache function //프로세서 ID가 ARM일경우 Cortex 등등인지를 확인하고, PC값에 값을 저장.
 THUMB(		addeq	r12, r3			) //THUMB이면 R3에 R12값 더해서 R12에 저장.
 THUMB(		moveq	pc, r12			) @ call cache function //R12값을 PC로 복사.
						//이제 이동함.

		add	r12, r12, #PROC_ENTRY_SIZE
		b	1b

/*
 * Table for cache operations.  This is basically:
 *   - CPU ID match
 *   - CPU ID mask
 *   - 'cache on' method instruction
 *   - 'cache off' method instruction
 *   - 'cache flush' method instruction
 *
 * We match an entry using: ((real_id ^ match) & mask) == 0
 *
 * Writethrough caches generally only need 'on' and 'off'
 * methods.  Writeback caches _must_ have the flush method
 * defined.
 */
		.align	2
		.type	proc_types,#object
proc_types:
		.word	0x41000000		@ old ARM ID
		.word	0xff00f000		//번지저장 마스크 후 복귀.
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)

		.word	0x41007000		@ ARM7/710
		.word	0xfff8fe00
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)

		.word	0x41807200		@ ARM720T (writethrough)
		.word	0xffffff00
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		mov	pc, lr
 THUMB(		nop				)

		.word	0x41007400		@ ARM74x
		.word	0xff00ff00
		W(b)	__armv3_mpu_cache_on
		W(b)	__armv3_mpu_cache_off
		W(b)	__armv3_mpu_cache_flush
		
		.word	0x41009400		@ ARM94x
		.word	0xff00ff00
		W(b)	__armv4_mpu_cache_on
		W(b)	__armv4_mpu_cache_off
		W(b)	__armv4_mpu_cache_flush

		.word	0x41069260		@ ARM926EJ-S (v5TEJ)
		.word	0xff0ffff0
		W(b)	__arm926ejs_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv5tej_mmu_cache_flush

		.word	0x00007000		@ ARM7 IDs
		.word	0x0000f000
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)

		@ Everything from here on will be the new ID system.

		.word	0x4401a100		@ sa110 / sa1100
		.word	0xffffffe0
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x6901b110		@ sa1110
		.word	0xfffffff0
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x56056900
		.word	0xffffff00		@ PXA9xx
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x56158000		@ PXA168
		.word	0xfffff000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv5tej_mmu_cache_flush

		.word	0x56050000		@ Feroceon
		.word	0xff0f0000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv5tej_mmu_cache_flush

#ifdef CONFIG_CPU_FEROCEON_OLD_ID
		/* this conflicts with the standard ARMv5TE entry */
		.long	0x41009260		@ Old Feroceon
		.long	0xff00fff0
		b	__armv4_mmu_cache_on
		b	__armv4_mmu_cache_off
		b	__armv5tej_mmu_cache_flush
#endif

		.word	0x66015261		@ FA526
		.word	0xff01fff1
		W(b)	__fa526_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__fa526_cache_flush

		@ These match on the architecture ID

		.word	0x00020000		@ ARMv4T
		.word	0x000f0000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x00050000		@ ARMv5TE
		.word	0x000f0000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x00060000		@ ARMv5TEJ
		.word	0x000f0000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv5tej_mmu_cache_flush

		.word	0x0007b000		@ ARMv6
		.word	0x000ff000
		W(b)	__armv6_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv6_mmu_cache_flush

		.word	0x000f0000		@ new CPU Id
		.word	0x000f0000
		W(b)	__armv7_mmu_cache_on
		W(b)	__armv7_mmu_cache_off
		W(b)	__armv7_mmu_cache_flush

		.word	0			@ unrecognised type
		.word	0
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)

		.size	proc_types, . - proc_types

		/*
		 * If you get a "non-constant expression in ".if" statement"
		 * error from the assembler on this line, check that you have
		 * not accidentally written a "b" instruction where you should
		 * have written W(b).
		 */
		.if (. - proc_types) % PROC_ENTRY_SIZE != 0
		.error "The size of one or more proc_types entries is wrong."
		.endif

/*
 * Turn off the Cache and MMU.  ARMv3 does not support
 * reading the control register, but ARMv4 does.
 *
 * On exit,
 *  r0, r1, r2, r3, r9, r12 corrupted
 * This routine must preserve:
 *  r4, r7, r8
 */
		.align	5
cache_off:	mov	r3, #12			@ cache_off function
		b	call_cache_fn

__armv4_mpu_cache_off:
		mrc	p15, 0, r0, c1, c0
		bic	r0, r0, #0x000d
		mcr	p15, 0, r0, c1, c0	@ turn MPU and cache off
		mov	r0, #0
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		mcr	p15, 0, r0, c7, c6, 0	@ flush D-Cache
		mcr	p15, 0, r0, c7, c5, 0	@ flush I-Cache
		mov	pc, lr

__armv3_mpu_cache_off:
		mrc	p15, 0, r0, c1, c0
		bic	r0, r0, #0x000d
		mcr	p15, 0, r0, c1, c0, 0	@ turn MPU and cache off
		mov	r0, #0
		mcr	p15, 0, r0, c7, c0, 0	@ invalidate whole cache v3
		mov	pc, lr

__armv4_mmu_cache_off:
#ifdef CONFIG_MMU
		mrc	p15, 0, r0, c1, c0
		bic	r0, r0, #0x000d
		mcr	p15, 0, r0, c1, c0	@ turn MMU and cache off
		mov	r0, #0
		mcr	p15, 0, r0, c7, c7	@ invalidate whole cache v4
		mcr	p15, 0, r0, c8, c7	@ invalidate whole TLB v4
#endif
		mov	pc, lr

__armv7_mmu_cache_off:
		mrc	p15, 0, r0, c1, c0
#ifdef CONFIG_MMU
		bic	r0, r0, #0x000d
#else
		bic	r0, r0, #0x000c
#endif
		mcr	p15, 0, r0, c1, c0	@ turn MMU and cache off
		mov	r12, lr
		bl	__armv7_mmu_cache_flush
		mov	r0, #0
#ifdef CONFIG_MMU
		mcr	p15, 0, r0, c8, c7, 0	@ invalidate whole TLB
#endif
		mcr	p15, 0, r0, c7, c5, 6	@ invalidate BTC
		mcr	p15, 0, r0, c7, c10, 4	@ DSB
		mcr	p15, 0, r0, c7, c5, 4	@ ISB
		mov	pc, r12

/*
 * Clean and flush the cache to maintain consistency.
 *
 * On exit,
 *  r1, r2, r3, r9, r10, r11, r12 corrupted
 * This routine must preserve:
 *  r4, r6, r7, r8
 */
		.align	5
cache_clean_flush:
		mov	r3, #16
		b	call_cache_fn

__armv4_mpu_cache_flush:
		tst	r4, #1
		movne	pc, lr
		mov	r2, #1
		mov	r3, #0
		mcr	p15, 0, ip, c7, c6, 0	@ invalidate D cache
		mov	r1, #7 << 5		@ 8 segments
1:		orr	r3, r1, #63 << 26	@ 64 entries
2:		mcr	p15, 0, r3, c7, c14, 2	@ clean & invalidate D index
		subs	r3, r3, #1 << 26
		bcs	2b			@ entries 63 to 0
		subs 	r1, r1, #1 << 5
		bcs	1b			@ segments 7 to 0

		teq	r2, #0
		mcrne	p15, 0, ip, c7, c5, 0	@ invalidate I cache
		mcr	p15, 0, ip, c7, c10, 4	@ drain WB
		mov	pc, lr
		
__fa526_cache_flush:
		tst	r4, #1
		movne	pc, lr
		mov	r1, #0
		mcr	p15, 0, r1, c7, c14, 0	@ clean and invalidate D cache
		mcr	p15, 0, r1, c7, c5, 0	@ flush I cache
		mcr	p15, 0, r1, c7, c10, 4	@ drain WB
		mov	pc, lr

__armv6_mmu_cache_flush:
		mov	r1, #0
		tst	r4, #1
		mcreq	p15, 0, r1, c7, c14, 0	@ clean+invalidate D
		mcr	p15, 0, r1, c7, c5, 0	@ invalidate I+BTB
		mcreq	p15, 0, r1, c7, c15, 0	@ clean+invalidate unified
		mcr	p15, 0, r1, c7, c10, 4	@ drain WB
		mov	pc, lr

__armv7_mmu_cache_flush:
		tst	r4, #1
		bne	iflush
		mrc	p15, 0, r10, c0, c1, 5	@ read ID_MMFR1
		tst	r10, #0xf << 16		@ hierarchical cache (ARMv7)
		mov	r10, #0
		beq	hierarchical
		mcr	p15, 0, r10, c7, c14, 0	@ clean+invalidate D
		b	iflush
hierarchical:
		mcr	p15, 0, r10, c7, c10, 5	@ DMB
		stmfd	sp!, {r0-r7, r9-r11}
		mrc	p15, 1, r0, c0, c0, 1	@ read clidr
		ands	r3, r0, #0x7000000	@ extract loc from clidr
		mov	r3, r3, lsr #23		@ left align loc bit field
		beq	finished		@ if loc is 0, then no need to clean
		mov	r10, #0			@ start clean at cache level 0
loop1:
		add	r2, r10, r10, lsr #1	@ work out 3x current cache level
		mov	r1, r0, lsr r2		@ extract cache type bits from clidr
		and	r1, r1, #7		@ mask of the bits for current cache only
		cmp	r1, #2			@ see what cache we have at this level
		blt	skip			@ skip if no cache, or just i-cache
		mcr	p15, 2, r10, c0, c0, 0	@ select current cache level in cssr
		mcr	p15, 0, r10, c7, c5, 4	@ isb to sych the new cssr&csidr
		mrc	p15, 1, r1, c0, c0, 0	@ read the new csidr
		and	r2, r1, #7		@ extract the length of the cache lines
		add	r2, r2, #4		@ add 4 (line length offset)
		ldr	r4, =0x3ff
		ands	r4, r4, r1, lsr #3	@ find maximum number on the way size
		clz	r5, r4			@ find bit position of way size increment
		ldr	r7, =0x7fff
		ands	r7, r7, r1, lsr #13	@ extract max number of the index size
loop2:
		mov	r9, r4			@ create working copy of max way size
loop3:
 ARM(		orr	r11, r10, r9, lsl r5	) @ factor way and cache number into r11
 ARM(		orr	r11, r11, r7, lsl r2	) @ factor index number into r11
 THUMB(		lsl	r6, r9, r5		)
 THUMB(		orr	r11, r10, r6		) @ factor way and cache number into r11
 THUMB(		lsl	r6, r7, r2		)
 THUMB(		orr	r11, r11, r6		) @ factor index number into r11
		mcr	p15, 0, r11, c7, c14, 2	@ clean & invalidate by set/way
		subs	r9, r9, #1		@ decrement the way
		bge	loop3
		subs	r7, r7, #1		@ decrement the index
		bge	loop2
skip:
		add	r10, r10, #2		@ increment cache number
		cmp	r3, r10
		bgt	loop1
finished:
		ldmfd	sp!, {r0-r7, r9-r11}
		mov	r10, #0			@ swith back to cache level 0
		mcr	p15, 2, r10, c0, c0, 0	@ select current cache level in cssr
iflush:
		mcr	p15, 0, r10, c7, c10, 4	@ DSB
		mcr	p15, 0, r10, c7, c5, 0	@ invalidate I+BTB
		mcr	p15, 0, r10, c7, c10, 4	@ DSB
		mcr	p15, 0, r10, c7, c5, 4	@ ISB
		mov	pc, lr

__armv5tej_mmu_cache_flush:
		tst	r4, #1
		movne	pc, lr
1:		mrc	p15, 0, r15, c7, c14, 3	@ test,clean,invalidate D cache
		bne	1b
		mcr	p15, 0, r0, c7, c5, 0	@ flush I cache
		mcr	p15, 0, r0, c7, c10, 4	@ drain WB
		mov	pc, lr

__armv4_mmu_cache_flush:
		tst	r4, #1
		movne	pc, lr
		mov	r2, #64*1024		@ default: 32K dcache size (*2)
		mov	r11, #32		@ default: 32 byte line size
		mrc	p15, 0, r3, c0, c0, 1	@ read cache type
		teq	r3, r9			@ cache ID register present?
		beq	no_cache_id
		mov	r1, r3, lsr #18
		and	r1, r1, #7
		mov	r2, #1024
		mov	r2, r2, lsl r1		@ base dcache size *2
		tst	r3, #1 << 14		@ test M bit
		addne	r2, r2, r2, lsr #1	@ +1/2 size if M == 1
		mov	r3, r3, lsr #12
		and	r3, r3, #3
		mov	r11, #8
		mov	r11, r11, lsl r3	@ cache line size in bytes
no_cache_id:
		mov	r1, pc
		bic	r1, r1, #63		@ align to longest cache line
		add	r2, r1, r2
1:
 ARM(		ldr	r3, [r1], r11		) @ s/w flush D cache
 THUMB(		ldr     r3, [r1]		) @ s/w flush D cache
 THUMB(		add     r1, r1, r11		)
		teq	r1, r2
		bne	1b

		mcr	p15, 0, r1, c7, c5, 0	@ flush I cache
		mcr	p15, 0, r1, c7, c6, 0	@ flush D cache
		mcr	p15, 0, r1, c7, c10, 4	@ drain WB
		mov	pc, lr

__armv3_mmu_cache_flush:
__armv3_mpu_cache_flush:
		tst	r4, #1
		movne	pc, lr
		mov	r1, #0
		mcr	p15, 0, r1, c7, c0, 0	@ invalidate whole cache v3
		mov	pc, lr

/*
 * Various debugging routines for printing hex characters and
 * memory, which again must be relocatable.
 */
#ifdef DEBUG
		.align	2
		.type	phexbuf,#object
phexbuf:	.space	12
		.size	phexbuf, . - phexbuf

@ phex corrupts {r0, r1, r2, r3}
phex:		adr	r3, phexbuf	// phexbuf의 주소 값을 r3에 저장
		mov	r2, #0		// r2를 0으로 셋팅
		strb	r2, [r3, r1]	// r2의 데이터 1byte를 r3(base) + r1(offset)의 위치에 저장
1:		subs	r1, r1, #1	// r1에서 1 빼기 (len-1)
		movmi	r0, r3		// N flag가 서있으면, r3의 값을 r0에 저장
		bmi	puts		// N flag가 서있으면, puts로 분기
		and	r2, r0, #15	// r0의 하위 4bit를 and masking해서 최하위 4bit 값만 남김 
		mov	r0, r0, lsr #4	// r0의 하위 4bit를 shift
		cmp	r2, #10		// r2를 10과 비교
		addge	r2, r2, #7	// 크면, r2에 7을 더함
		add	r2, r2, #'0'	// 아스키 코드 '0' 값을 더함
		strb	r2, [r3, r1]	// 바뀐 값을 r3(phexbuf)에 저장
		b	1b		// 반복

@ puts corrupts {r0, r1, r2, r3}
puts:		loadsp	r3, r1
1:		ldrb	r2, [r0], #1
		teq	r2, #0
		moveq	pc, lr
2:		writeb	r2, r3	// writeb 매크로 정의에 따라 처리 (CPU의 cp14 transmit 레지스터 또는 uart의 transmit 레지스터로 쓰기)
		mov	r1, #0x00020000	// r1에 20000 저장 -> 2^18 시간 동안, 개발자가 맘대로 지정
3:		subs	r1, r1, #1	// r1에서 1을 뺀다 (subS 이므로 Z flag 셋팅 됨)
		bne	3b		// 3b(backward)로 이동 (r1이 0이 될 때까지) -> 문자 입력 될 때까지 대기하기
		teq	r2, #'\n'	// r2의 값이 linefeed(줄바뀜)인지 확인 -> 만족 시 Z flag 셋팅
		moveq	r2, #'\r'	// Z flag가 서있으면, r2에 carriage return 저장 (프롬프트 위치 맨 앞으로 이동하기 위함)
		beq	2b		// Z flag가 서있으면, 2b로 이동
		teq	r0, #0		// r0가 0이면, Z flag 셋팅
		bne	1b		// Z flag가 안서있으면, 1b로 이동
		mov	pc, lr		// lr(link 레지스터)을 pc로 복구 (매크로 호출했던 위치(kputc의 end)로 돌아감)
@ putc corrupts {r0, r1, r2, r3}
putc:
		mov	r2, r0	// r0(val)의 값을 r2에 저장
		mov	r0, #0	// r0를 0으로 초기화
		loadsp	r3, r1	// loadsp 매크로 정의에 따라 처리
				// (DEBUG define 설정에 따라 달라짐, 디버그 base address 설정 또는 아무 처리 안함)
		b	2b	// back to 2b(backward) -> 상단에 있는 2: 라벨로 이동

@ memdump corrupts {r0, r1, r2, r3, r10, r11, r12, lr}
memdump:	mov	r12, r0
		mov	r10, lr
		mov	r11, #0
2:		mov	r0, r11, lsl #2
		add	r0, r0, r12
		mov	r1, #8
		bl	phex
		mov	r0, #':'
		bl	putc
1:		mov	r0, #' '
		bl	putc
		ldr	r0, [r12, r11, lsl #2]
		mov	r1, #8
		bl	phex
		and	r0, r11, #7
		teq	r0, #3
		moveq	r0, #' '
		bleq	putc
		and	r0, r11, #7
		add	r11, r11, #1
		teq	r0, #7
		bne	1b
		mov	r0, #'\n'
		bl	putc
		cmp	r11, #64
		blt	2b
		mov	pc, r10
#endif

		.ltorg

#ifdef CONFIG_ARM_VIRT_EXT
.align 5
__hyp_reentry_vectors:
		W(b)	.			@ reset
		W(b)	.			@ undef
		W(b)	.			@ svc
		W(b)	.			@ pabort
		W(b)	.			@ dabort
		W(b)	__enter_kernel		@ hyp
		W(b)	.			@ irq
		W(b)	.			@ fiq
#endif /* CONFIG_ARM_VIRT_EXT */

__enter_kernel:
		mov	r0, #0			@ must be 0
 ARM(		mov	pc, r4		)	@ call kernel
 M_CLASS(	add	r4, r4, #1	)	@ enter in Thumb mode for M class
 THUMB(		bx	r4		)	@ entry point is always ARM for A/R classes

reloc_code_end:

		.align
		.section ".stack", "aw", %nobits
.L_user_stack:	.space	4096
.L_user_stack_end:
