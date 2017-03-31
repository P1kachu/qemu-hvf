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
                                              VMCS_GUEST_ ## name , \
                                              seg.selector);                    \
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

#define cap2ctrl(cap, ctrl) (((ctrl) | ((cap) & 0xffffffff)) & ((cap) >> 32))
#define get_bit(integer, n) (int)((integer & ( 1 << n )) >> n)
#define print_pinbased_controls(tmp)\
        printf("VMExec Pin-Based controls: 0x%llx\n", tmp); \
        printf("  Pin-Based - External-interrupt exiting                    : %d\n", get_bit(tmp, 0));\
        printf("  Pin-Based - NMI exiting                                   : %d\n", get_bit(tmp, 3));\
        printf("  Pin-Based - Virtual NMIs                                  : %d\n", get_bit(tmp, 5));\
        printf("  Pin-Based - Activate VMX preemption timer                 : %d\n", get_bit(tmp, 6));\
        printf("  Pin-Based - Process posted interrupts                     : %d\n", get_bit(tmp, 7));\

#define print_procbased1_controls(tmp)\
        printf("VMExec Proc-Based controls 1: 0x%llx\n", tmp); \
        printf("  Proc-Based1 - Interrupt-window exiting                    : %d\n", get_bit(tmp, 2));\
        printf("  Proc-Based1 - Use TSC offsetting                          : %d\n", get_bit(tmp, 3));\
        printf("  Proc-Based1 - HLT exiting                                 : %d\n", get_bit(tmp, 7));\
        printf("  Proc-Based1 - INVLPG exiting                              : %d\n", get_bit(tmp, 9));\
        printf("  Proc-Based1 - MWAIT exiting                               : %d\n", get_bit(tmp, 10));\
        printf("  Proc-Based1 - RDPMC exiting                               : %d\n", get_bit(tmp, 11));\
        printf("  Proc-Based1 - RDTSC exiting                               : %d\n", get_bit(tmp, 12));\
        printf("  Proc-Based1 - CR3-load exiting                            : %d\n", get_bit(tmp, 15));\
        printf("  Proc-Based1 - CR3-store exiting                           : %d\n", get_bit(tmp, 16));\
        printf("  Proc-Based1 - CR8-load exiting                            : %d\n", get_bit(tmp, 19));\
        printf("  Proc-Based1 - CR8-store exiting                           : %d\n", get_bit(tmp, 20));\
        printf("  Proc-Based1 - Use TPR shadow                              : %d\n", get_bit(tmp, 21));\
        printf("  Proc-Based1 - NMI-window exiting                          : %d\n", get_bit(tmp, 22));\
        printf("  Proc-Based1 - MOV-DR exiting                              : %d\n", get_bit(tmp, 23));\
        printf("  Proc-Based1 - Unconditional I/O exiting                   : %d\n", get_bit(tmp, 24));\
        printf("  Proc-Based1 - Use I/O bitmaps                             : %d\n", get_bit(tmp, 25));\
        printf("  Proc-Based1 - Monitor trap flag                           : %d\n", get_bit(tmp, 27));\
        printf("  Proc-Based1 - Use MSR bitmaps                             : %d\n", get_bit(tmp, 28));\
        printf("  Proc-Based1 - MONITOR exiting                             : %d\n", get_bit(tmp, 29));\
        printf("  Proc-Based1 - PAUSE exiting                               : %d\n", get_bit(tmp, 30));\
        printf("  Proc-Based1 - Activate secondary controls                 : %d\n", get_bit(tmp, 31));\

#define print_procbased2_controls(tmp)\
        printf("VMExec Proc-Based controls 2: 0x%llx\n", tmp); \
        printf("  Proc-Based2 - Virtualize APIC accesses                    : %d\n", get_bit(tmp, 0));\
        printf("  Proc-Based2 - Enable EPT                                  : %d\n", get_bit(tmp, 1));\
        printf("  Proc-Based2 - Descriptor-table exiting                    : %d\n", get_bit(tmp, 2));\
        printf("  Proc-Based2 - Enable RDTSCP                               : %d\n", get_bit(tmp, 3));\
        printf("  Proc-Based2 - Virtualize x2APIC mode                      : %d\n", get_bit(tmp, 4));\
        printf("  Proc-Based2 - Enable VPID                                 : %d\n", get_bit(tmp, 5));\
        printf("  Proc-Based2 - WBINVD exiting                              : %d\n", get_bit(tmp, 6));\
        printf("  Proc-Based2 - Unrestricted guest                          : %d\n", get_bit(tmp, 7));\
        printf("  Proc-Based2 - APIC-register virtualization                : %d\n", get_bit(tmp, 8));\
        printf("  Proc-Based2 - Virtual-interrupt delivery                  : %d\n", get_bit(tmp, 9));\
        printf("  Proc-Based2 - PAUSE-loop exiting                          : %d\n", get_bit(tmp, 10));\
        printf("  Proc-Based2 - RDRAND exiting                              : %d\n", get_bit(tmp, 11));\
        printf("  Proc-Based2 - Enable INVPCID                              : %d\n", get_bit(tmp, 12));\
        printf("  Proc-Based2 - Enable VM functions                         : %d\n", get_bit(tmp, 13));\
        printf("  Proc-Based2 - VMCS shadowing                              : %d\n", get_bit(tmp, 14));\
        printf("  Proc-Based2 - Enable ENCLS exiting                        : %d\n", get_bit(tmp, 15));\
        printf("  Proc-Based2 - RDSEED exiting                              : %d\n", get_bit(tmp, 16));\
        printf("  Proc-Based2 - Enable PML                                  : %d\n", get_bit(tmp, 17));\
        printf("  Proc-Based2 - EPT-violation #VE                           : %d\n", get_bit(tmp, 18));\
        printf("  Proc-Based2 - Conceal VMX non-root operation from Intel PT: %d\n", get_bit(tmp, 19));\
        printf("  Proc-Based2 - Enable XSAVES/XRSTORS                       : %d\n", get_bit(tmp, 20));\
        printf("  Proc-Based2 - Mode-based execute control for EPT          : %d\n", get_bit(tmp, 22));\
        printf("  Proc-Based2 - Use TSC scaling                             : %d\n", get_bit(tmp, 25));\

#define print_vmentry_controls(tmp) \
        printf("VMEntry controls: 0x%llx\n", tmp); \
        printf("  VMEntry - Load debug controls                             : %d\n", get_bit(tmp, 2));\
        printf("  VMEntry - IA-32e mode guest                               : %d\n", get_bit(tmp, 9));\
        printf("  VMEntry - Entry to SMM                                    : %d\n", get_bit(tmp, 10));\
        printf("  VMEntry - Deactivate dual-monitor                         : %d\n", get_bit(tmp, 11));\
        printf("  VMEntry - Load IA32_PERF_GLOBAL_CTRL                      : %d\n", get_bit(tmp, 13));\
        printf("  VMEntry - Load IA32_PAT                                   : %d\n", get_bit(tmp, 14));\
        printf("  VMEntry - Load IA32_EFER                                  : %d\n", get_bit(tmp, 15));\
        printf("  VMEntry - Load IA32_BNDCFGS                               : %d\n", get_bit(tmp, 16));\
        printf("  VMEntry - Conceal VM entries from Intel PT                : %d\n", get_bit(tmp, 17));

#define print_vmexit_controls(tmp) \
        printf("VMExit controls: 0x%llx\n", tmp); \
        printf("  VMExit - Save debug controls                              : %d\n", get_bit(tmp, 2));\
        printf("  VMExit - Host address-space size                          : %d\n", get_bit(tmp, 9));\
        printf("  VMExit - Load A32_PERF_GLOBAL_CTRL                        : %d\n", get_bit(tmp, 12));\
        printf("  VMExit - Acknowledge interrupt on exit                    : %d\n", get_bit(tmp, 15));\
        printf("  VMExit - Save IA32_PAT                                    : %d\n", get_bit(tmp, 18));\
        printf("  VMExit - Load IA32_PAT                                    : %d\n", get_bit(tmp, 19));\
        printf("  VMExit - Save IA32_EFER                                   : %d\n", get_bit(tmp, 20));\
        printf("  VMExit - Load IA32_EFER                                   : %d\n", get_bit(tmp, 21));\
        printf("  VMExit - Save VMX-preemption timer value                  : %d\n", get_bit(tmp, 22));\
        printf("  VMExit - Clear IA32_BNDCFGS                               : %d\n", get_bit(tmp, 23));\
        printf("  VMExit - Conceal VM exits from Intel PT                   : %d\n", get_bit(tmp, 24));\



extern bool hvf_allowed;

hv_return_t hvf_vcpu_exec(CPUState *cpu);
hv_return_t hvf_vcpu_init(CPUState *cpu);
hv_return_t hvf_memory_init(MachineState *ms);
hv_return_t hvf_update_state(CPUState *cpu);


// DEBUG
const char *interrupt_type(uint64_t val);
void hvf_controls(CPUState *cpu);
void hvf_check_consistency(CPUState *cpu);
void check_vm_entry(CPUState *cpu);

#else

# define hvf_enabled() (0)

#endif /* CONFIG_HVF */

#endif /* HVF_H */
