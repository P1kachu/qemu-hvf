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
                return hv_vcpu_write_register(vcpu,
                                vmcs_offset,
                                *general_register);
        } else {
                return hv_vcpu_read_register(vcpu,
                                vmcs_offset,
                                general_register);
        }
}


static hv_return_t hvf_put_regs(CPUState *cpu)
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
        ret |= hvf_getput_reg(vcpuid, HV_X86_DR0, &env->dr[0], HVF_SET_REGS);
        ret |= hvf_getput_reg(vcpuid, HV_X86_DR1, &env->dr[1], HVF_SET_REGS);
        ret |= hvf_getput_reg(vcpuid, HV_X86_DR2, &env->dr[2], HVF_SET_REGS);
        ret |= hvf_getput_reg(vcpuid, HV_X86_DR3, &env->dr[3], HVF_SET_REGS);
        ret |= hvf_getput_reg(vcpuid, HV_X86_DR4, &env->dr[4], HVF_SET_REGS);
        ret |= hvf_getput_reg(vcpuid, HV_X86_DR5, &env->dr[5], HVF_SET_REGS);
        ret |= hvf_getput_reg(vcpuid, HV_X86_DR6, &env->dr[6], HVF_SET_REGS);
        ret |= hvf_getput_reg(vcpuid, HV_X86_DR7, &env->dr[7], HVF_SET_REGS);

        EXIT_IF_FAIL(hvf_put_regs);

        return ret;
}

static hv_return_t hvf_put_sregs(CPUState *cpu)
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
        SET_SEG(vcpuid, LDTR, env->ldt);

        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_CR0, env->cr[0]);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_CR3, env->cr[3]);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_CR4, env->cr[4]);

        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_IDTR_BASE, env->idt.base);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_IDTR_LIMIT, env->idt.limit);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_GDTR_BASE, env->gdt.base);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_GDTR_LIMIT, env->gdt.limit);

        EXIT_IF_FAIL(hvf_put_sregs);

        return ret;

}

static hv_return_t hvf_init_msr(CPUState *cpu)
{
        hv_return_t ret = 0;
        hv_vcpuid_t vcpuid = cpu->vcpuid;
        X86CPU *x86_cpu = X86_CPU(cpu);
        CPUX86State *env = &x86_cpu->env;

        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_STAR, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_LSTAR, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_CSTAR, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_FMASK, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_FSBASE, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_GSBASE, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_KERNELGSBASE, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_TSC_AUX, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_IA32_SYSENTER_CS, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_IA32_SYSENTER_EIP, HVF_MSR_ENABLE);

        ret |= hv_vcpu_write_msr(vcpuid, MSR_IA32_SYSENTER_CS, env->sysenter_cs);
        ret |= hv_vcpu_write_msr(vcpuid, MSR_IA32_SYSENTER_EIP, env->sysenter_eip);
        ret |= hv_vcpu_write_msr(vcpuid, MSR_IA32_SYSENTER_ESP, env->sysenter_esp);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_IA32_EFER, env->efer);

        ret |= hv_vcpu_write_msr(vcpuid, MSR_STAR, env->star);
        ret |= hv_vcpu_write_msr(vcpuid, MSR_CSTAR, env->cstar);
        ret |= hv_vcpu_write_msr(vcpuid, MSR_KERNELGSBASE, env->kernelgsbase);
        ret |= hv_vcpu_write_msr(vcpuid, MSR_FMASK, env->fmask);
        ret |= hv_vcpu_write_msr(vcpuid, MSR_LSTAR, env->lstar);

        ret |= hv_vcpu_write_msr(vcpuid, MSR_GSBASE, env->segs[R_GS].base);
        ret |= hv_vcpu_write_msr(vcpuid, MSR_FSBASE, env->segs[R_FS].base);

        EXIT_IF_FAIL(hvf_init_msr);

        DPRINTF("HVF: MSR initialized\n");

        return ret;
}

hv_return_t hvf_update_state(CPUState *cpu)
{
        hv_return_t ret = 0;
#if 0
        ret = hvf_put_regs(cpu);
        ret |= hvf_put_sregs(cpu);
#endif

        uint64_t tmp;
        hv_vcpu_read_register(cpu->vcpuid, HV_X86_RAX, &tmp);
        printf("\033[32;1mRAX: 0x%llx\033[0m\n", tmp);
        hv_vcpu_read_register(cpu->vcpuid, HV_X86_RCX, &tmp);
        printf("\033[32;1mRCX: 0x%llx\033[0m\n", tmp);
        hv_vcpu_read_register(cpu->vcpuid, HV_X86_RIP, &tmp);
        printf("\033[32;1mRIP: 0x%llx\033[0m\n", tmp);

        return ret;
}

hv_return_t hvf_vcpu_init(CPUState *cpu)
{
        DPRINTF("HVF: hvf_vcpu_init on CPU %d\n", cpu->vcpuid);

        hv_return_t ret = hv_vcpu_create(&cpu->vcpuid, HV_VCPU_DEFAULT);
        EXIT_IF_FAIL(hv_vcpu_create);

#if 0
        uint64_t tmp;
        ret |= hv_vmx_read_capability(HV_VMX_CAP_PINBASED, &tmp);
        ret |= hv_vmx_vcpu_write_vmcs(cpu->vcpuid,
                        VMCS_CTRL_PIN_BASED,
                        cap2ctrl(tmp, 0));
        ret |= hv_vmx_read_capability(HV_VMX_CAP_PROCBASED, &tmp);
        ret |= hv_vmx_vcpu_write_vmcs(cpu->vcpuid,
                        VMCS_CTRL_CPU_BASED,
                        cap2ctrl(tmp, CPU_BASED_HLT
                                | CPU_BASED_MWAIT
                                | CPU_BASED_IRQ_WND
                                | CPU_BASED_TPR_SHADOW)
                        | CPU_BASED_SECONDARY_CTLS);

        ret |= hv_vmx_read_capability(HV_VMX_CAP_PROCBASED2, &tmp);
        ret |= hv_vmx_vcpu_write_vmcs(cpu->vcpuid,
                        VMCS_CTRL_CPU_BASED2,
                        cap2ctrl(tmp, CPU_BASED2_VIRTUAL_APIC));

        ret |= hv_vmx_read_capability(HV_VMX_CAP_ENTRY, &tmp);
        ret |= hv_vmx_vcpu_write_vmcs(cpu->vcpuid,
                        VMCS_CTRL_VMENTRY_CONTROLS,
                        cap2ctrl(tmp, 0));

        ret |= hv_vmx_vcpu_write_vmcs(cpu->vcpuid, VMCS_CTRL_TPR_THRESHOLD, 0);
#endif

        ret = hvf_init_msr(cpu);

        // Debug
        ret |= hv_vcpu_write_register(cpu->vcpuid, HV_X86_RIP, 0xfff0);
        ret |= hv_vcpu_write_register(cpu->vcpuid, HV_X86_RAX, 0x01234567);
        ret |= hv_vcpu_write_register(cpu->vcpuid, HV_X86_RCX, 0x89abcdef);

#define RESET_SEG(vcpu, seg, base, lmt, ar)                                       \
        do {                                                                    \
                ret |= hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_ ## seg ## _BASE, base);\
                ret |= hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_ ## seg ## _LIMIT, lmt);\
                ret |= hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_ ## seg ## _AR, ar);    \
        } while (0)                                                            \

        ret |= hv_vmx_vcpu_write_vmcs(cpu->vcpuid, VMCS_GUEST_CS, 0xf000);
        RESET_SEG(cpu->vcpuid, CS, 0xffff0000, 0xffff, 0xc09b);
        RESET_SEG(cpu->vcpuid, DS, 0, 0xffff, 0xc093);
        RESET_SEG(cpu->vcpuid, SS, 0, 0xffff, 0xc093);
        RESET_SEG(cpu->vcpuid, ES, 0, 0xffff, 0xc093);
        RESET_SEG(cpu->vcpuid, FS, 0, 0, 0x93);
        RESET_SEG(cpu->vcpuid, GS, 0, 0, 0x93);
        RESET_SEG(cpu->vcpuid, TR, 0, 0, 0x83);
        RESET_SEG(cpu->vcpuid, LDTR, 0, 0, 0x10000);
        ret |= hv_vmx_vcpu_write_vmcs(cpu->vcpuid, VMCS_CTRL_CPU_BASED,
                        (CPU_BASED_HLT | CPU_BASED_CR8_LOAD | CPU_BASED_CR8_STORE));
        ret |= hv_vmx_vcpu_write_vmcs(cpu->vcpuid, VMCS_GUEST_CR4, 0x2000);
        ret |= hv_vmx_vcpu_write_vmcs(cpu->vcpuid, VMCS_GUEST_CR0, 0x31);
        ret |= hv_vcpu_write_register(cpu->vcpuid, HV_X86_RFLAGS, 0x2);
        ret |= hv_vmx_vcpu_write_vmcs(cpu->vcpuid, VMCS_CTRL_EXC_BITMAP, 0xffffffff);

        ret |= hvf_update_state(cpu);
        hvf_controls(cpu);

        return ret;
}

