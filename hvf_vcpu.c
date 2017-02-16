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
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_IDTR_BASE, env->idt.base);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_IDTR_LIMIT, env->idt.limit);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_GDTR_BASE, env->gdt.base);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_GDTR_LIMIT, env->gdt.limit);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_CR0, env->cr[0]);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_CR3, env->cr[3]);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_CR4, env->cr[4]);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_IA32_EFER, env->efer);

//#define CPU_BASED_CTRL (CPU_BASED_HLT | CPU_BASED_CR8_LOAD | CPU_BASED_CR8_STORE)
//        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_CTRL_CPU_BASED, CPU_BASED_CTRL);
#if 0
        if (env->interrupt_injected >= 0) {
                sregs.interrupt_bitmap[env->interrupt_injected / 64] |=
                        (uint64_t)1 << (env->interrupt_injected % 64);
        }
        sregs.apic_base = cpu_get_apic_base(cpu->apic_state);
        uint64_t cr8 = cpu_get_apic_tpr(cpu->apic_state);
#endif

        EXIT_IF_FAIL(hvf_put_sregs);

        return ret;

}

#define PRINT_VALUE(name) printf("  --> " #name ": 0x%llx\n", (unsigned long long)env->name);
void hvf_debug(CPUState *cpu)
{
        CPUX86State *env = &X86_CPU(cpu)->env;

        printf("----\n");

        PRINT_VALUE(segs[R_CS].base);
        PRINT_VALUE(segs[R_CS].limit);
        PRINT_VALUE(segs[R_CS].flags);
        PRINT_VALUE(segs[R_DS].base);
        PRINT_VALUE(segs[R_DS].limit);
        PRINT_VALUE(segs[R_DS].flags);
        PRINT_VALUE(segs[R_ES].base);
        PRINT_VALUE(segs[R_ES].limit);
        PRINT_VALUE(segs[R_ES].flags);
        PRINT_VALUE(segs[R_FS].base);
        PRINT_VALUE(segs[R_FS].limit);
        PRINT_VALUE(segs[R_FS].flags);
        PRINT_VALUE(segs[R_GS].base);
        PRINT_VALUE(segs[R_GS].limit);
        PRINT_VALUE(segs[R_GS].flags);
        PRINT_VALUE(segs[R_SS].base);
        PRINT_VALUE(segs[R_SS].limit);
        PRINT_VALUE(segs[R_SS].flags);
        PRINT_VALUE(idt.base);
        PRINT_VALUE(idt.limit);
        PRINT_VALUE(idt.flags);
        PRINT_VALUE(gdt.base);
        PRINT_VALUE(gdt.limit);
        PRINT_VALUE(gdt.flags);
        PRINT_VALUE(ldt.base);
        PRINT_VALUE(ldt.limit);
        PRINT_VALUE(ldt.flags);
        PRINT_VALUE(cr[0]);
        PRINT_VALUE(cr[3]);
        PRINT_VALUE(cr[4]);
        PRINT_VALUE(efer);

        PRINT_VALUE(eip);
        PRINT_VALUE(eflags);
        PRINT_VALUE(regs[R_EAX]);
        PRINT_VALUE(regs[R_EBX]);
        PRINT_VALUE(regs[R_ECX]);
        PRINT_VALUE(regs[R_EDX]);
        PRINT_VALUE(regs[R_ESI]);
        PRINT_VALUE(regs[R_EDI]);
        PRINT_VALUE(regs[R_ESP]);
        PRINT_VALUE(regs[R_EBP]);
        PRINT_VALUE(regs[8]);
        PRINT_VALUE(regs[9]);
        PRINT_VALUE(regs[10]);
        PRINT_VALUE(regs[11]);
        PRINT_VALUE(regs[12]);
        PRINT_VALUE(regs[13]);
        PRINT_VALUE(regs[14]);
        PRINT_VALUE(regs[15]);

        printf("----\n");



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

        EXIT_IF_FAIL(hvf_put_regs);

        return ret;
}

static hv_return_t hvf_init_msr(CPUState *cpu)
{
        hv_return_t ret = 0;
        hv_vcpuid_t vcpuid = cpu->vcpuid;
        X86CPU *x86_cpu = X86_CPU(cpu);
        CPUX86State *env = &x86_cpu->env;

        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_IA32_SYSENTER_CS, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_IA32_SYSENTER_EIP, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_IA32_SYSENTER_ESP, HVF_MSR_ENABLE);

        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_SYSENTER_EIP, env->sysenter_eip);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_SYSENTER_ESP, env->sysenter_esp);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_IA32_SYSENTER_CS, env->sysenter_cs);

#ifdef TARGET_X86_64
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_KERNELGSBASE, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_FMASK, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_LSTAR, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_CSTAR, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_STAR, HVF_MSR_ENABLE);
#endif

#if 1
        // Need to check why
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_GSBASE, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_FSBASE, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_IA32_TSC, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_TSC_AUX, HVF_MSR_ENABLE);
        //MSR_PAT?
#endif

        EXIT_IF_FAIL(hvf_init_msr);

        DPRINTF("HVF: MSR initialized\n");

        return ret;
}

hv_return_t hvf_update_state(CPUState *cpu)
{
        hv_return_t ret = 0;

        ret = hvf_put_regs(cpu);

        ret = hvf_put_sregs(cpu);

        return ret;
}

hv_return_t hvf_vcpu_init(CPUState *cpu)
{
        DPRINTF("HVF: hvf_vcpu_init on CPU %d\n", cpu->vcpuid);

        hv_return_t ret = hv_vcpu_create(&cpu->vcpuid, HV_VCPU_DEFAULT);
        EXIT_IF_FAIL(hv_vcpu_create);

        ret = hvf_init_msr(cpu);

        ret = hvf_update_state(cpu);

		// DEBUG
#if 0
        hv_return_t vcpuid = cpu->vcpuid;
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_CTRL_PIN_BASED, 0x3f);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_CTRL_CPU_BASED, 0xb5186dfa);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_CTRL_CPU_BASED2, 0xaa);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_CTRL_VMEXIT_CONTROLS, 0x236fff);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_CTRL_VMENTRY_CONTROLS, 0x91ff);
		hv_vmx_vcpu_write_vmcs(cpu->vcpuid, 0x00004004, 1 << 18);
#endif
		return ret;
}

