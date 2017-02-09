#include "qemu/osdep.h"

#include <Hypervisor/hv.h>

#include "cpu.h"
#include "sysemu/hvf.h"
#include "qemu/module.h"
#include "sysemu/accel.h"

static hv_return_t hvf_getput_reg(hv_vcpuid_t vcpu,
                                  int vmcs_offset,
                                  uint64_t *general_register,
                                  int set)
{
        if (set == HVF_SET_REGS) {
                return hv_vcpu_write_register(vcpu, vmcs_offset, *general_register);
        } else {
                return hv_vcpu_read_register(vcpu, vmcs_offset, general_register);
        }
}

#if 0
static hv_return_t hvf_get_general_registers(hv_vcpuid_t vcpu,
                                             struct hvf_general_regs *regs)
{
        hv_return_t ret = 0;

        ret |= hvf_getput_reg(vcpu, HV_X86_RIP, &regs->hv_x86_rip, HVF_GET_REGS);
        ret |= hvf_getput_reg(vcpu, HV_X86_RFLAGS, &regs->hv_x86_rflags, HVF_GET_REGS);
        ret |= hvf_getput_reg(vcpu, HV_X86_RAX, &regs->hv_x86_rax, HVF_GET_REGS);
        ret |= hvf_getput_reg(vcpu, HV_X86_RBX, &regs->hv_x86_rbx, HVF_GET_REGS);
        ret |= hvf_getput_reg(vcpu, HV_X86_RCX, &regs->hv_x86_rcx, HVF_GET_REGS);
        ret |= hvf_getput_reg(vcpu, HV_X86_RDX, &regs->hv_x86_rdx, HVF_GET_REGS);
        ret |= hvf_getput_reg(vcpu, HV_X86_RSI, &regs->hv_x86_rsi, HVF_GET_REGS);
        ret |= hvf_getput_reg(vcpu, HV_X86_RDI, &regs->hv_x86_rdi, HVF_GET_REGS);
        ret |= hvf_getput_reg(vcpu, HV_X86_RSP, &regs->hv_x86_rsp, HVF_GET_REGS);
        ret |= hvf_getput_reg(vcpu, HV_X86_RBP, &regs->hv_x86_rbp, HVF_GET_REGS);
        ret |= hvf_getput_reg(vcpu, HV_X86_R8, &regs->hv_x86_r8, HVF_GET_REGS);
        ret |= hvf_getput_reg(vcpu, HV_X86_R9, &regs->hv_x86_r9, HVF_GET_REGS);
        ret |= hvf_getput_reg(vcpu, HV_X86_R10, &regs->hv_x86_r10, HVF_GET_REGS);
        ret |= hvf_getput_reg(vcpu, HV_X86_R11, &regs->hv_x86_r11, HVF_GET_REGS);
        ret |= hvf_getput_reg(vcpu, HV_X86_R12, &regs->hv_x86_r12, HVF_GET_REGS);
        ret |= hvf_getput_reg(vcpu, HV_X86_R13, &regs->hv_x86_r13, HVF_GET_REGS);
        ret |= hvf_getput_reg(vcpu, HV_X86_R14, &regs->hv_x86_r14, HVF_GET_REGS);
        ret |= hvf_getput_reg(vcpu, HV_X86_R15, &regs->hv_x86_r15, HVF_GET_REGS);

        return ret;
}
#endif

static hv_return_t hvf_put_init_sregs(CPUState *cpu)
{
        CPUX86State *env = &X86_CPU(cpu)->env;
        hv_vcpuid_t vcpuid = cpu->vcpuid;

        hv_return_t ret = 0;

        SET_SEG(vcpuid, CS, env->segs[R_CS]);
        SET_SEG(vcpuid, DS, env->segs[R_DS]);
        SET_SEG(vcpuid, ES, env->segs[R_ES]);
        SET_SEG(vcpuid, FS, env->segs[R_FS]);
        SET_SEG(vcpuid, GS, env->segs[R_GS]);
        SET_SEG(vcpuid, SS, env->segs[R_SS]);
        SET_SEG(vcpuid, TR, env->tr);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_IDTR_BASE, env->idt.base);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_IDTR_LIMIT, env->idt.limit);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_GDTR_BASE, env->gdt.base);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_GDTR_LIMIT, env->gdt.limit);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_CR0, env->cr[0]);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_CR3, env->cr[3]);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_CR4, env->cr[4]);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_IA32_EFER, env->efer);

#if 0
        if (env->interrupt_injected >= 0) {
                sregs.interrupt_bitmap[env->interrupt_injected / 64] |=
                        (uint64_t)1 << (env->interrupt_injected % 64);
        }
        sregs.apic_base = cpu_get_apic_base(cpu->apic_state);
        uint64_t cr8 = cpu_get_apic_tpr(cpu->apic_state);
#endif

        DPRINTF("HVF: Special registers initialized\n");

        return ret;

}

static hv_return_t hvf_put_init_regs(CPUState *cpu)
{
        X86CPU *x86_cpu = X86_CPU(cpu);
        CPUX86State *env = &x86_cpu->env;
        hv_vcpuid_t vcpuid = cpu->vcpuid;
        hv_return_t ret = 0;

        ret |= hvf_getput_reg(vcpuid, HV_X86_RIP, &env->eip, HVF_SET_REGS);
        ret |= hvf_getput_reg(vcpuid, HV_X86_RFLAGS, &env->eflags, HVF_SET_REGS);
        ret |= hvf_getput_reg(vcpuid, HV_X86_RAX, &env->regs[R_EAX], HVF_SET_REGS);
        ret |= hvf_getput_reg(vcpuid, HV_X86_RBX, &env->regs[R_EBX], HVF_SET_REGS);
        ret |= hvf_getput_reg(vcpuid, HV_X86_RCX, &env->regs[R_ECX], HVF_SET_REGS);
        ret |= hvf_getput_reg(vcpuid, HV_X86_RDX, &env->regs[R_EDX], HVF_SET_REGS);
        ret |= hvf_getput_reg(vcpuid, HV_X86_RSI, &env->regs[R_ESI], HVF_SET_REGS);
        ret |= hvf_getput_reg(vcpuid, HV_X86_RDI, &env->regs[R_EDI], HVF_SET_REGS);
        ret |= hvf_getput_reg(vcpuid, HV_X86_RSP, &env->regs[R_ESP], HVF_SET_REGS);
        ret |= hvf_getput_reg(vcpuid, HV_X86_RBP, &env->regs[R_EBP], HVF_SET_REGS);
        ret |= hvf_getput_reg(vcpuid, HV_X86_R8, &env->regs[8], HVF_SET_REGS);
        ret |= hvf_getput_reg(vcpuid, HV_X86_R9, &env->regs[9], HVF_SET_REGS);
        ret |= hvf_getput_reg(vcpuid, HV_X86_R10, &env->regs[10], HVF_SET_REGS);
        ret |= hvf_getput_reg(vcpuid, HV_X86_R11, &env->regs[11], HVF_SET_REGS);
        ret |= hvf_getput_reg(vcpuid, HV_X86_R12, &env->regs[12], HVF_SET_REGS);
        ret |= hvf_getput_reg(vcpuid, HV_X86_R13, &env->regs[13], HVF_SET_REGS);
        ret |= hvf_getput_reg(vcpuid, HV_X86_R14, &env->regs[14], HVF_SET_REGS);
        ret |= hvf_getput_reg(vcpuid, HV_X86_R15, &env->regs[15], HVF_SET_REGS);

        DPRINTF("HVF: Registers initialized\n");

        return ret;
}

static hv_return_t hvf_init_msr(CPUState *cpu)
{
        hv_return_t ret = 0;
        hv_vcpuid_t vcpuid = cpu->vcpuid;

        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_IA32_SYSENTER_CS, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_IA32_SYSENTER_EIP, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_IA32_SYSENTER_ESP, HVF_MSR_ENABLE);

#ifdef TARGET_X86_64
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_CSTAR, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_KERNELGSBASE, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_FMASK, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_LSTAR, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_STAR, HVF_MSR_ENABLE);
#endif

#if 0
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_GSBASE, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_FSBASE, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_IA32_TSC, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_TSC_AUX, HVF_MSR_ENABLE);
        MSR_PAT?
#endif

        DPRINTF("HVF: MSR initialized\n");

        return ret;
}

hv_return_t hvf_vcpu_init(CPUState *cpu)
{
        DPRINTF("HVF: hvf_vcpu_init on CPU %d\n", cpu->vcpuid);

        hv_return_t ret = hv_vcpu_create(&cpu->vcpuid, HV_VCPU_DEFAULT);
        EXIT_IF_FAIL(hv_vcpu_create);

        ret = hvf_put_init_regs(cpu);
        EXIT_IF_FAIL(hvf_put_init_regs);

        ret = hvf_put_init_sregs(cpu);
        EXIT_IF_FAIL(hvf_put_init_sregs);

        ret = hvf_init_msr(cpu);
        EXIT_IF_FAIL(hvf_init_msr);

        return 0;
}

