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

#define HVF_GET_REGS    0
#define HVF_SET_REGS    1
#define HVF_MSR_DISABLE 0
#define HVF_MSR_ENABLE  1

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

#define SET_SEG(vcpu, name, seg)                                                \
        do {                                                                    \
                ret |= hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_ ## name ## _BASE, seg.base);\
                ret |= hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_ ## name ## _LIMIT, seg.limit);\
                ret |= hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_ ## name ## _AR, seg.flags);    \
                DPRINTF("HVF: Setting " #name " (Base: 0x%llx - Limit: 0x%x - flags: 0x%x)\n", seg.base, seg.limit, seg.flags);\
        } while (0)                                                            \


hv_return_t hvf_vcpu_exec(CPUState *cpu);
hv_return_t hvf_vcpu_init(CPUState *cpu);
hv_return_t hvf_memory_init(MachineState *ms);

#else

# define hvf_enabled() (0)

#endif /* CONFIG_HVF */

#endif /* HVF_H */
