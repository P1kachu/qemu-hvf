#include "qemu/osdep.h"

#include <Hypervisor/hv.h>

#include "sysemu/accel.h"
#include "qemu/module.h"
#include "hvf.h"

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

hv_return_t hvf_cpu_exec(hv_vcpuid_t vcpu)
{
        printf("HVF: hvf_cpu_exec() --> ");

        uint64_t exit_reason = hvf_get_exit_reason(vcpu);

        switch(exit_reason) {
                default:
                        fprintf(stderr,
                                "HVF: Unhandled exit reason (%lld: %s)\n",
                                exit_reason,
                                exit_reason_str(exit_reason & 0xffff));
                        exit(1);
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
