#ifndef HVF_H
#define HVF_H

#include "qom/cpu.h"

struct hvf_general_regs {
        uint64_t hv_x86_rip;
        uint64_t hv_x86_rflags;
        uint64_t hv_x86_rax;
        uint64_t hv_x86_rbx;
        uint64_t hv_x86_rcx;
        uint64_t hv_x86_rdx;
        uint64_t hv_x86_rsi;
        uint64_t hv_x86_rdi;
        uint64_t hv_x86_rsp;
        uint64_t hv_x86_rbp;
        uint64_t hv_x86_r8;
        uint64_t hv_x86_r9;
        uint64_t hv_x86_r10;
        uint64_t hv_x86_r11;
        uint64_t hv_x86_r12;
        uint64_t hv_x86_r13;
        uint64_t hv_x86_r14;
        uint64_t hv_x86_r15;
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

#define SET_SEG(vcpu, name, seg)                                                \
        do {                                                                    \
                hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_ ## name ## _BASE, seg.base);\
                hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_ ## name ## _LIMIT, seg.limit);\
                hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_ ## name ## _AR, seg.flags);    \
        } while (0)                                                            \


hv_return_t hvf_vcpu_exec(CPUState *cpu);
hv_return_t hvf_vcpu_init(CPUState *cpu);

#else

# define hvf_enabled() (0)

#endif /* CONFIG_HVF */

#endif /* HVF_H */
