#ifndef HVF_H
#define HVF_H

#ifdef CONFIG_HVF

#include "qom/cpu.h"

# include <Hypervisor/hv.h>
# include <Hypervisor/hv_vmx.h>
# include <Hypervisor/hv_arch_vmx.h>

# define TYPE_HVF_ACCEL ACCEL_CLASS_NAME("hvf")
# define hvf_enabled() (hvf_allowed)

#define HVF_GET_REGS      0
#define HVF_SET_REGS      1
#define HVF_MSR_DISABLE   0
#define HVF_MSR_ENABLE    1
#define HVF_REGION_DELETE 0
#define HVF_REGION_ADD    1

#define EXIT_IF_FAIL(func) \
        if (ret) {         \
                fprintf(stderr, "HVF: " #func  " failed (%x)\n", ret); \
                exit(1); \
        }

#define DEBUG_HVF
#ifdef DEBUG_HVF
#define DPRINTF(fmt, ...) \
        do { fprintf(stderr, fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
        do { } while (0)
#endif

#define SET_SEG(vcpu, name, seg)                                            \
        do {                                                                \
                ret |= hv_vmx_vcpu_write_vmcs(vcpu,                         \
                                              VMCS_GUEST_ ## name ## _BASE, \
                                              seg.base);                    \
                ret |= hv_vmx_vcpu_write_vmcs(vcpu,                         \
                                              VMCS_GUEST_ ## name ## _LIMIT,\
                                              seg.limit);                   \
                ret |= hv_vmx_vcpu_write_vmcs(vcpu,                         \
                                              VMCS_GUEST_ ## name ## _AR,   \
                                              seg.flags >> 8);              \
        } while (0)                                                         \

extern bool hvf_allowed;

hv_return_t hvf_vcpu_exec(CPUState *cpu);
hv_return_t hvf_vcpu_init(CPUState *cpu);
hv_return_t hvf_memory_init(MachineState *ms);
hv_return_t hvf_update_state(CPUState *cpu);
void hvf_debug(CPUState *cpu);

#else

# define hvf_enabled() (0)

#endif /* CONFIG_HVF */

#endif /* HVF_H */
