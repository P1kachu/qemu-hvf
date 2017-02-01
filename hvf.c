#include "qemu/osdep.h"

#include <Hypervisor/hv.h>

#include "cpu.h"
#include "hvf.h"
#include "qemu/module.h"
#include "sysemu/accel.h"

bool hvf_allowed = true;

static int hvf_get_exit_reason(hv_vcpuid_t vcpu)
{
        uint64_t val = 0;
        hv_return_t err = hv_vmx_vcpu_read_vmcs(vcpu, VMCS_RO_EXIT_REASON, &val);

        if (err) {
                fprintf(stderr,
                        "HFV: hvf_get_exit_reason failed with %d\n",
                        err);
                exit(1);
        }

        return val;
}

static const char *exit_reason_str(uint64_t reason)
{
#define S(V) case V: return #V
        switch (reason) {
                S(VMX_REASON_EXC_NMI);
                S(VMX_REASON_IRQ);
                S(VMX_REASON_TRIPLE_FAULT);
                S(VMX_REASON_INIT);
                S(VMX_REASON_SIPI);
                S(VMX_REASON_IO_SMI);
                S(VMX_REASON_OTHER_SMI);
                S(VMX_REASON_IRQ_WND);
                S(VMX_REASON_VIRTUAL_NMI_WND);
                S(VMX_REASON_TASK);
                S(VMX_REASON_CPUID);
                S(VMX_REASON_GETSEC);
                S(VMX_REASON_HLT);
                S(VMX_REASON_INVD);
                S(VMX_REASON_INVLPG);
                S(VMX_REASON_RDPMC);
                S(VMX_REASON_RDTSC);
                S(VMX_REASON_RSM);
                S(VMX_REASON_VMCALL);
                S(VMX_REASON_VMCLEAR);
                S(VMX_REASON_VMLAUNCH);
                S(VMX_REASON_VMPTRLD);
                S(VMX_REASON_VMPTRST);
                S(VMX_REASON_VMREAD);
                S(VMX_REASON_VMRESUME);
                S(VMX_REASON_VMWRITE);
                S(VMX_REASON_VMOFF);
                S(VMX_REASON_VMON);
                S(VMX_REASON_MOV_CR);
                S(VMX_REASON_MOV_DR);
                S(VMX_REASON_IO);
                S(VMX_REASON_RDMSR);
                S(VMX_REASON_WRMSR);
                S(VMX_REASON_VMENTRY_GUEST);
                S(VMX_REASON_VMENTRY_MSR);
                S(VMX_REASON_MWAIT);
                S(VMX_REASON_MTF);
                S(VMX_REASON_MONITOR);
                S(VMX_REASON_PAUSE);
                S(VMX_REASON_VMENTRY_MC);
                S(VMX_REASON_TPR_THRESHOLD);
                S(VMX_REASON_APIC_ACCESS);
                S(VMX_REASON_VIRTUALIZED_EOI);
                S(VMX_REASON_GDTR_IDTR);
                S(VMX_REASON_LDTR_TR);
                S(VMX_REASON_EPT_VIOLATION);
                S(VMX_REASON_EPT_MISCONFIG);
                S(VMX_REASON_EPT_INVEPT);
                S(VMX_REASON_RDTSCP);
                S(VMX_REASON_VMX_TIMER_EXPIRED);
                S(VMX_REASON_INVVPID);
                S(VMX_REASON_WBINVD);
                S(VMX_REASON_XSETBV);
                S(VMX_REASON_APIC_WRITE);
                S(VMX_REASON_RDRAND);
                S(VMX_REASON_INVPCID);
                S(VMX_REASON_VMFUNC);
                S(VMX_REASON_RDSEED);
                S(VMX_REASON_XSAVES);
                S(VMX_REASON_XRSTORS);

                default:
                return "VMX_REASON_???";
        }
#undef S
}

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
        //struct hvf_sregs sregs;
        hv_vcpuid_t vcpuid = cpu->vcpuid;

#if 0
        if (env->interrupt_injected >= 0) {
                sregs.interrupt_bitmap[env->interrupt_injected / 64] |=
                        (uint64_t)1 << (env->interrupt_injected % 64);
        }
        sregs.apic_base = cpu_get_apic_base(cpu->apic_state);
        uint64_t cr8 = cpu_get_apic_tpr(cpu->apic_state);
#endif


        hv_return_t ret = 0;

        SET_SEG(vcpuid, CS, env->segs[R_CS]);
        SET_SEG(vcpuid, DS, env->segs[R_DS]);
        SET_SEG(vcpuid, ES, env->segs[R_ES]);
        SET_SEG(vcpuid, FS, env->segs[R_FS]);
        SET_SEG(vcpuid, GS, env->segs[R_GS]);
        SET_SEG(vcpuid, SS, env->segs[R_SS]);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_IDTR_BASE, env->idt.base);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_IDTR_LIMIT, env->idt.limit);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_GDTR_BASE, env->gdt.base);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_GDTR_LIMIT, env->gdt.limit);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_CR0, env->cr[0]);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_CR3, env->cr[3]);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_CR4, env->cr[4]);
        //ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_CR2, env->cr[2]);
        //ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_CR8, cr8);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_IA32_EFER, env->efer);
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

    return ret;
}
hv_return_t hvf_vcpu_init(CPUState *cpu)
{
        printf("HVF: hvf_vcpu_init %d\n", cpu->vcpuid);

        hv_return_t ret = hv_vcpu_create(&cpu->vcpuid, HV_VCPU_DEFAULT);

        if (ret) {
                fprintf(stderr, "HVF: hv_vcpu_create failed (%x)\n", ret);
                exit(1);
        }

        ret = hvf_put_init_regs(cpu);
        if (ret) {
                fprintf(stderr, "HVF: hvf_put_init_regs failed (%x)\n", ret);
                exit(1);
        }

        ret = hvf_put_init_sregs(cpu);
        if (ret) {
                fprintf(stderr, "HVF: hvf_put_init_sregs failed (%x)\n", ret);
                exit(1);
        }
        return 0;
}

hv_return_t hvf_vcpu_exec(CPUState *cpu)
{
        fprintf(stderr, "HVF: hvf_vcpu_exec() -- ");

        uint64_t exit_reason = hvf_get_exit_reason(cpu->vcpuid);

        switch(exit_reason) {
                case VMX_REASON_EXC_NMI:
                        fprintf(stderr, "NMI\n");
                        return 1;
                        break;
                default:
                        fprintf(stderr,
                                "Unhandled exit reason (%lld: %s)\n",
                                exit_reason,
                                exit_reason_str(exit_reason & 0xffff));
                        return 1;
        }
        return 0;
}

static int hvf_init(MachineState *ms)
{
        printf("HVF: Init\n");
        hv_return_t ret = 0;

        ret = hv_vm_create(HV_VM_DEFAULT);
        if (ret) {
                fprintf(stderr, "HVF: hv_vm_create failed with %x\n", ret);
                exit(1);
        }

// TODO: Remove this too
#define VM_START_ADDRESS 0x0
#define VM_MEM_SIZE      (1024 * 1024)
#define PERM_RWX (HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC)

        //TODO: remove valloc
        void *vm_mem = valloc(VM_MEM_SIZE);
        if (!vm_mem) {
                fprintf(stderr, "HVF: vm memory allocation failed\n");
                exit(1);
        }

        ret = hv_vm_map(vm_mem, VM_START_ADDRESS, VM_MEM_SIZE, PERM_RWX);
        if (ret) {
                fprintf(stderr, "HVF: vm_vm_map failed with %x\n", ret);
                exit(1);
        }

        return 0;
}

static void hvf_accel_class_init(ObjectClass *oc, void *data)
{
    AccelClass *ac = ACCEL_CLASS(oc);
    ac->name = "HVF";
    ac->init_machine = hvf_init;
    ac->allowed = &hvf_allowed;
}

static const TypeInfo hvf_accel_type = {
    .name = TYPE_HVF_ACCEL,
    .parent = TYPE_ACCEL,
    .class_init = hvf_accel_class_init,
    .instance_size = sizeof(HVFState),
};

static void hvf_type_init(void)
{
    type_register_static(&hvf_accel_type);
}

type_init(hvf_type_init);
