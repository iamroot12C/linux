/*
 *  linux/arch/arm/kernel/devtree.c
 *
 *  Copyright (C) 2009 Canonical Ltd. <jeremy.kerr@canonical.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/init.h>
#include <linux/export.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/bootmem.h>
#include <linux/memblock.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/smp.h>

#include <asm/cputype.h>
#include <asm/setup.h>
#include <asm/page.h>
#include <asm/smp_plat.h>
#include <asm/mach/arch.h>
#include <asm/mach-types.h>


#ifdef CONFIG_SMP
extern struct of_cpu_method __cpu_method_of_table[];

static const struct of_cpu_method __cpu_method_of_table_sentinel
	__used __section(__cpu_method_of_table_end);


static int __init set_smp_ops_by_method(struct device_node *node)
{
	const char *method;
	struct of_cpu_method *m = __cpu_method_of_table;

	if (of_property_read_string(node, "enable-method", &method))
		return 0;

	for (; m->method; m++)
		if (!strcmp(m->method, method)) {
			smp_set_ops(m->ops);
			return 1;
		}

	return 0;
}
#else
static inline int set_smp_ops_by_method(struct device_node *node)
{
	return 1;
}
#endif


/*
 * arm_dt_init_cpu_maps - Function retrieves cpu nodes from the device tree
 * and builds the cpu logical map array containing MPIDR values related to
 * logical cpus
 *
 * Updates the cpu possible mask with the number of parsed cpu nodes
 */
void __init arm_dt_init_cpu_maps(void)
{
	/*
	 * Temp logical map is initialized with UINT_MAX values that are
	 * considered invalid logical map entries since the logical map must
	 * contain a list of MPIDR[23:0] values where MPIDR[31:24] must
	 * read as 0.
	 */
	struct device_node *cpu, *cpus;
	int found_method = 0;
	u32 i, j, cpuidx = 1;
	u32 mpidr = is_smp() ? read_cpuid_mpidr() & MPIDR_HWID_BITMASK : 0;

	u32 tmp_map[NR_CPUS] = { [0 ... NR_CPUS-1] = MPIDR_INVALID };
	bool bootcpu_valid = false;
	cpus = of_find_node_by_path("/cpus");

	if (!cpus)
		return;

	for_each_child_of_node(cpus, cpu) {
		u32 hwid;

		if (of_node_cmp(cpu->type, "cpu"))
			continue;

		pr_debug(" * %s...\n", cpu->full_name);
		/*
		 * A device tree containing CPU nodes with missing "reg"
		 * properties is considered invalid to build the
		 * cpu_logical_map.
		 */
		if (of_property_read_u32(cpu, "reg", &hwid)) {
			pr_debug(" * %s missing reg property\n",
				     cpu->full_name);
			return;
		}

		/*
		 * 8 MSBs must be set to 0 in the DT since the reg property
		 * defines the MPIDR[23:0].
		 */
		if (hwid & ~MPIDR_HWID_BITMASK)
			return;

		/*
		 * Duplicate MPIDRs are a recipe for disaster.
		 * Scan all initialized entries and check for
		 * duplicates. If any is found just bail out.
		 * temp values were initialized to UINT_MAX
		 * to avoid matching valid MPIDR[23:0] values.
		 */
		for (j = 0; j < cpuidx; j++)
			if (WARN(tmp_map[j] == hwid, "Duplicate /cpu reg "
						     "properties in the DT\n"))
				return;

		/*
		 * Build a stashed array of MPIDR values. Numbering scheme
		 * requires that if detected the boot CPU must be assigned
		 * logical id 0. Other CPUs get sequential indexes starting
		 * from 1. If a CPU node with a reg property matching the
		 * boot CPU MPIDR is detected, this is recorded so that the
		 * logical map built from DT is validated and can be used
		 * to override the map created in smp_setup_processor_id().
		 */
		if (hwid == mpidr) {
			i = 0;
			bootcpu_valid = true;
		} else {
			i = cpuidx++;
		}

		if (WARN(cpuidx > nr_cpu_ids, "DT /cpu %u nodes greater than "
					       "max cores %u, capping them\n",
					       cpuidx, nr_cpu_ids)) {
			cpuidx = nr_cpu_ids;
			break;
		}

		tmp_map[i] = hwid;

		if (!found_method)
			found_method = set_smp_ops_by_method(cpu);
	}

	/*
	 * Fallback to an enable-method in the cpus node if nothing found in
	 * a cpu node.
	 */
	if (!found_method)
		set_smp_ops_by_method(cpus);

	if (!bootcpu_valid) {
		pr_warn("DT missing boot CPU MPIDR[23:0], fall back to default cpu_logical_map\n");
		return;
	}

	/*
	 * Since the boot CPU node contains proper data, and all nodes have
	 * a reg property, the DT CPU list can be considered valid and the
	 * logical map created in smp_setup_processor_id() can be overridden
	 */
	for (i = 0; i < cpuidx; i++) {
		set_cpu_possible(i, true);
		cpu_logical_map(i) = tmp_map[i];
		pr_debug("cpu logical map 0x%x\n", cpu_logical_map(i));
	}
}

bool arch_match_cpu_phys_id(int cpu, u64 phys_id)
{
	return phys_id == cpu_logical_map(cpu);
}
// Iteration 돌면서 1개씩 추가.
static const void * __init arch_get_next_mach(const char *const **match)
{
	static const struct machine_desc *mdesc = __arch_info_begin;
	const struct machine_desc *m = mdesc;

	if (m >= __arch_info_end)
		return NULL;

	mdesc++;
	*match = m->dt_compat;
	return m;
}

/**
 * setup_machine_fdt - Machine setup when an dtb was passed to the kernel
 * @dt_phys: physical address of dt blob
 *
 * If a dtb was passed to the kernel in r2, then use it to choose the
 * correct machine_desc and to setup the system.
 */
const struct machine_desc * __init setup_machine_fdt(unsigned int dt_phys)
{
	const struct machine_desc *mdesc, *mdesc_best = NULL;

#ifdef CONFIG_ARCH_MULTIPLATFORM
	DT_MACHINE_START(GENERIC_DT, "Generic DT based system") // name으로 dtb 검색
		// 여기다 확장
	MACHINE_END // 내용 : "};" : DT_MACHINE_START랑 세트로 다님. 이유는 확장을 위해서.

	mdesc_best = &__mach_desc_GENERIC_DT; //위에서 DT_MACHINE_START 에서 설정한 값을 mdesc_best 에다가 setting
#endif
	// boot/head.S 에서 넘겨주었던 atags_pointer를 넘겨준다.
	if (!dt_phys || !early_init_dt_verify(phys_to_virt(dt_phys))) // 주소가 존재하지 않거나, device tree 가 존재하지 않으면, 즉 DTB가 없으면 NULL을 반환
		return NULL;

	// boot/head.S에서 가져온 atgs_pointer와 맞는 디바이스 매칭한다. 디바이스 트리에서 맞는거를 찾는다.
	mdesc = of_flat_dt_match_machine(mdesc_best, arch_get_next_mach);

	// multi platform 이면 절대 여기를 들어가지 않는다.
	// why??
	if (!mdesc) { // dtb가 없는 경우(커널 모듈과 드라이버 모듈이 mismatch)
		const char *prop;
		int size;
		unsigned long dt_root;

		early_print("\nError: unrecognized/unsupported " // message 찍어줌.
			    "device tree compatible list:\n[ ");

		dt_root = of_get_flat_dt_root();  // NULL 가져옴
		prop = of_get_flat_dt_prop(dt_root, "compatible", &size);
		while (size > 0) {
			early_print("'%s' ", prop);
			size -= strlen(prop) + 1;
			prop += strlen(prop) + 1;
		}
		early_print("]\n\n");

		dump_machine_table(); /* does not return */ // machine table 값들 찍어주고 freeze.
	}

	/* We really don't want to do this, but sometimes firmware provides buggy data */
	if (mdesc->dt_fixup) 
		mdesc->dt_fixup(); // dt_fixup 멤버 변수는 보통 null이며 특별히 펌웨어에 문제가 있어 수정되어야 하는 경우 이 멤버 변수에 fixup 관련 함수를 등록하여 사용한다.

	early_init_dt_scan_nodes(); // command line을 flatted_dtb에 설정.

	/* Change machine number to match the mdesc we're using */
	__machine_arch_type = mdesc->nr; // __machine_arch_type을 설정.
									// 보드 버전에 맞게 machine number를 수정;

	return mdesc; // machine_descriptor 반환.
}
