#include <asm/setup.h>
#include <libfdt.h>

#if defined(CONFIG_ARM_ATAG_DTB_COMPAT_CMDLINE_EXTEND)
#define do_extend_cmdline 1
#else
#define do_extend_cmdline 0
#endif

#define NR_BANKS 16

static int node_offset(void *fdt, const char *node_path)
{
	int offset = fdt_path_offset(fdt, node_path);
	if (offset == -FDT_ERR_NOTFOUND)
		offset = fdt_add_subnode(fdt, 0, node_path);
	return offset;
}

static int setprop(void *fdt, const char *node_path, const char *property,
		   uint32_t *val_array, int size)
{
	int offset = node_offset(fdt, node_path);
	if (offset < 0)
		return offset;
	return fdt_setprop(fdt, offset, property, val_array, size);
}

static int setprop_string(void *fdt, const char *node_path,
			  const char *property, const char *string)
{
	int offset = node_offset(fdt, node_path);
	if (offset < 0)
		return offset;
	return fdt_setprop_string(fdt, offset, property, string);
}

static int setprop_cell(void *fdt, const char *node_path,
			const char *property, uint32_t val)
{
	int offset = node_offset(fdt, node_path);
	if (offset < 0)
		return offset;
	return fdt_setprop_cell(fdt, offset, property, val);
}

static const void *getprop(const void *fdt, const char *node_path,
			   const char *property, int *len)
{
	int offset = fdt_path_offset(fdt, node_path);

	if (offset == -FDT_ERR_NOTFOUND)
		return NULL;

	return fdt_getprop(fdt, offset, property, len);
}

static uint32_t get_cell_size(const void *fdt)
{
	int len;
	uint32_t cell_size = 1;
	const uint32_t *size_len =  getprop(fdt, "/", "#size-cells", &len); //size-cells라고해서 하드코딩되있음, 그 사이즈를 가져옴.

	if (size_len)
		cell_size = fdt32_to_cpu(*size_len);
	return cell_size;
}

static void merge_fdt_bootargs(void *fdt, const char *fdt_cmdline)
{
	char cmdline[COMMAND_LINE_SIZE];
	const char *fdt_bootargs;
	char *ptr = cmdline;
	int len = 0;

	/* copy the fdt command line into the buffer */
	fdt_bootargs = getprop(fdt, "/chosen", "bootargs", &len);
	if (fdt_bootargs)
		if (len < COMMAND_LINE_SIZE) {
			memcpy(ptr, fdt_bootargs, len);
			/* len is the length of the string
			 * including the NULL terminator */
			ptr += len - 1;
		}

	/* and append the ATAG_CMDLINE */
	if (fdt_cmdline) {
		len = strlen(fdt_cmdline);
		if (ptr - cmdline + len + 2 < COMMAND_LINE_SIZE) {
			*ptr++ = ' ';
			memcpy(ptr, fdt_cmdline, len);
			ptr += len;
		}
	}
	*ptr = '\0';

	setprop_string(fdt, "/chosen", "bootargs", cmdline);
}

/*
 * Convert and fold provided ATAGs into the provided FDT.
 *
 * REturn values:
 *    = 0 -> pretend success
 *    = 1 -> bad ATAG (may retry with another possible ATAG pointer)
 *    < 0 -> error from libfdt
 */

// FDT (Flattened Device Tree).
// 커널에서 부트파라미터 넘기는 형식이 atag.!!
// head.S에서 디바이스트리 정보를 FDT형식에 맞게 전달해주면 굳이 이렇게 변환안해도 됨.
int atags_to_fdt(void *atag_list, void *fdt, int total_space)
{
	struct tag *atag = atag_list;
	/* In the case of 64 bits memory size, need to reserve 2 cells for
	 * address and size for each bank */
	uint32_t mem_reg_property[2 * 2 * NR_BANKS];
	int memcount = 0;
	int ret, memsize;

	/* make sure we've got an aligned pointer */ // align 32bit
	if ((u32)atag_list & 0x3)
		return 1;

	/* if we get a DTB here we're done already */
	// atag_list 가 FDT_MAGIC 과 같으면 변환할 필요가 없음
	// 이미 atag_list는 fdt 형식으로 제공됨.
	if (*(u32 *)atag_list == fdt32_to_cpu(FDT_MAGIC))
	       return 0;

	/*
	 * 2015. 08. 29. (토) 21:42:30 KST
	 * Driving end..
	 * Minkyung Kim
	 * */

	/* validate the ATAG */
	// atag는 반드시 ATAG_CORE부터 시작되어야 함
	if (atag->hdr.tag != ATAG_CORE ||		// 결국 tag는 ATAG_CORE값이어야하고
	    (atag->hdr.size != tag_size(tag_core) &&	// size가 tagsize이거나  2이면 넘어감.
	     						// tag_size에서 (>>2) 하는것은 align을 위한것?
	     atag->hdr.size != 2))
		return 1;

	/* let's give it all the room it could need */
	ret = fdt_open_into(fdt, fdt, total_space);	// fdt에 저장하기위해 fdt할당
	if (ret < 0)
		return ret;

	for_each_tag(atag, atag_list) {
		if (atag->hdr.tag == ATAG_CMDLINE/*=54410009*/) {	// tag구조체에서 9번째 요소가 tag_cmd관련 요소인데 이렇게 하나하나  요소를 hdr.tag를 통해 하나씩 비교한다.
			/* Append the ATAGS command line to the device tree
			 * command line.
			 * NB: This means that if the same parameter is set in
			 * the device tree and in the tags, the one from the
			 * tags will be chosen.
			 */
			if (do_extend_cmdline)	// 확장한다는 DEFINE이 서있으면 =1.
				merge_fdt_bootargs(fdt,
						   atag->u.cmdline.cmdline);
			else
				setprop_string(fdt, "/chosen", "bootargs",
					       atag->u.cmdline.cmdline);
		} else if (atag->hdr.tag == ATAG_MEM) {
			if (memcount >= sizeof(mem_reg_property)/4)
				continue;
			if (!atag->u.mem.size)
				continue;
			memsize = get_cell_size(fdt);
	
			if (memsize == 2) {	// OS 64bit or 32bit 에 따라 Cell Size가 정해짐
						// 눈으로 확인하고싶으면
						// arch/arm/boot/dts/skeleton.dts, skeleton64.dts 를 열어보자.
						// #size-cells 가 정의되어 있다.
				/* if memsize is 2, that means that
				 * each data needs 2 cells of 32 bits,
				 * so the data are 64 bits */
				uint64_t *mem_reg_prop64 =
					(uint64_t *)mem_reg_property;
				mem_reg_prop64[memcount++] =
					cpu_to_fdt64(atag->u.mem.start);
				mem_reg_prop64[memcount++] =
					cpu_to_fdt64(atag->u.mem.size);
			} else {
				mem_reg_property[memcount++] =
					cpu_to_fdt32(atag->u.mem.start);
				mem_reg_property[memcount++] =
					cpu_to_fdt32(atag->u.mem.size);
			}

		} else if (atag->hdr.tag == ATAG_INITRD2) {
			uint32_t initrd_start, initrd_size;
			initrd_start = atag->u.initrd.start;
			initrd_size = atag->u.initrd.size;
			setprop_cell(fdt, "/chosen", "linux,initrd-start",
					initrd_start);
			setprop_cell(fdt, "/chosen", "linux,initrd-end",
					initrd_start + initrd_size);
		}
	}

	if (memcount) {
		// fdt를 open한 메모리에 memcpy를 한다.
		// 그러면 지금까지의 atag정보들이 fdt쭉 들어간다.
		setprop(fdt, "/memory", "reg", mem_reg_property,
			4 * memcount/*=16*/ * memsize/*=1or2*/);
	}

	return fdt_pack(fdt);
}
/*
   2015. 09. 05. (토) 21:25:32 KST
   Name : DH Kim
   End Driving ...
*/


