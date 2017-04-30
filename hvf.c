#include "qemu/osdep.h"

#include <Hypervisor/hv.h>

#include "cpu.h"
#include "qemu/module.h"
#include "qemu/main-loop.h"
#include "sysemu/accel.h"
#include "sysemu/hvf.h"
#include "exec/address-spaces.h"


bool hvf_allowed = true;

static int hvf_get_exit_reason(hv_vcpuid_t vcpu)
{
        uint64_t val = 0;
        hv_return_t err = hv_rd_vmcs(vcpu, VMCS_RO_EXIT_REASON, &val);

        if (err) {
                DPRINTF("HFV: hvf_get_exit_reason failed with %d\n",
                                err);
                exit(1);
        }

        return val;
}


static int hvf_init(MachineState *ms)
{
        DPRINTF("HVF: Init\n");
        hv_return_t ret = 0;

        ret = hv_vm_create(HV_VM_DEFAULT);
        if (ret) {
                fprintf(stderr, "HVF: hv_vm_create failed with %x\n", ret);
                exit(1);
        }

        hvf_memory_init(ms);

        return 0;
}

static hv_return_t hvf_handle_io(CPUState *cpu, uint64_t exit_qual, uint64_t ins_len)
{
        uint32_t access_size  = (exit_qual & 7) + 1;
        uint32_t is_out       = (exit_qual & (1 << 3)) == 0;
        uint32_t is_string    = (exit_qual & (1 << 4)) != 0;
        //uint32_t is_rep       = (exit_qual & (1 << 5)) != 0;
        //uint32_t is_immediate = (exit_qual & (1 << 6)) != 0;
        uint32_t port         = exit_qual >> 16;

        uint64_t rip, rax, count;
        hv_rd_reg(cpu->vcpuid, HV_X86_RIP, &rip);
        hv_rd_reg(cpu->vcpuid, HV_X86_RAX, &rax);

        uint8_t *data = (uint8_t *)rax;

        X86CPU *x86_cpu = X86_CPU(cpu);
        CPUX86State *env = &x86_cpu->env;
        MemTxAttrs attrs = (MemTxAttrs) { .secure = (env->hflags & HF_SMM_MASK) != 0 };

        count = 1; // TODO: Add proper handling

        for (int i = 0; i < count; ++i) {
                address_space_rw(&address_space_io,
                                port,
                                attrs,
                                data,
                                access_size,
                                is_out);
                data += access_size;
        }

        hv_wr_reg(cpu->vcpuid, HV_X86_RIP, rip + ins_len);

        return 0;
}

hv_return_t hvf_vcpu_exec(CPUState *cpu)
{
        uint64_t intr_info, tmp, exit_reason, qualification, ins_len, curr_rip;
        hv_return_t ret = 0;
        hv_vcpuid_t vcpu = cpu->vcpuid;

        qemu_mutex_unlock_iothread();

        hvf_update_state(cpu);

        ret = hv_vcpu_run(vcpu);

        if (ret) {
                fprintf(stderr, "HVF: hv_vcpu_run failed with %x\n", ret);
                exit(1);
        }

        exit_reason = hvf_get_exit_reason(vcpu) & 0xffff;
        hv_rd_vmcs(vcpu, VMCS_RO_VMEXIT_INSTR_LEN, &ins_len);
        hv_rd_vmcs(vcpu, VMCS_RO_EXIT_QUALIFIC, &qualification);
        hv_rd_reg(vcpu, HV_X86_RIP, &curr_rip);

        qemu_mutex_lock_iothread();

        hvf_debug_print_vmexit(exit_reason);

        switch(exit_reason) {
                case VMX_REASON_EXC_NMI:
                        hv_rd_vmcs(vcpu, VMCS_RO_VMEXIT_IRQ_INFO, &intr_info);
                        hvf_debug_print_nmi(intr_info);
                        break;

                case VMX_REASON_EPT_VIOLATION:
                        hvf_debug_print_ept(vcpu);
                        break;

                case VMX_REASON_IO:
                        hvf_handle_io(cpu, qualification, ins_len);
                        break;

                case VMX_REASON_TRIPLE_FAULT:
                        hv_rd_vmcs(vcpu, VMCS_GUEST_PHYSICAL_ADDRESS, &tmp);
                        DPRINTF("  GPA: %llx\n", tmp);
                        abort();
                        break;

                case VMX_REASON_HLT:
                case VMX_REASON_IRQ:
                case VMX_REASON_VMENTRY_GUEST:
                default:
                        DPRINTF("Unhandled exit reason, aborting\n");
                        ret = 1;
                        //hvf_check_consistency(cpu);
                        abort(); // TODO: Remove
        }


        return ret;
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
        //    .instance_size = sizeof(HVFState),
};

static void hvf_type_init(void)
{
        type_register_static(&hvf_accel_type);
}

type_init(hvf_type_init);
