#ifndef HVF_H
#define HVF_H

#include "qom/cpu.h"

struct hvf_general_regs {
        uint64_t HV_X86_RIP;
        uint64_t HV_X86_RFLAGS;
        uint64_t HV_X86_RAX;
        uint64_t HV_X86_RBX;
        uint64_t HV_X86_RCX;
        uint64_t HV_X86_RDX;
        uint64_t HV_X86_RSI;
        uint64_t HV_X86_RDI;
        uint64_t HV_X86_RSP;
        uint64_t HV_X86_RBP;
        uint64_t HV_X86_R8;
        uint64_t HV_X86_R9;
        uint64_t HV_X86_R10;
        uint64_t HV_X86_R11;
        uint64_t HV_X86_R12;
        uint64_t HV_X86_R13;
        uint64_t HV_X86_R14;
        uint64_t HV_X86_R15;
};

typedef struct HVFState {
} HVFState;

extern bool hvf_allowed;

#ifdef CONFIG_HVF

# include <Hypervisor/hv.h>
# include <Hypervisor/hv_vmx.h>
# include <Hypervisor/hv_arch_vmx.h>

# define TYPE_HVF_ACCEL ACCEL_CLASS_NAME("hvf")
# define hvf_enabled() (hvf_allowed)

#define HVF_GET_REGS 0
#define HVF_SET_REGS 1

hv_return_t hvf_vcpu_exec(CPUState *cpu);
hv_return_t hvf_vcpu_init(CPUState *cpu);

#else

# define hvf_enabled() (0)

#endif /* CONFIG_HVF */

#endif /* HVF_H */
