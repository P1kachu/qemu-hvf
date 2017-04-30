#include "qemu/osdep.h"

#include "cpu.h"
#include "sysemu/hvf.h"

void hvf_debug_print_regs(hv_vcpuid_t vcpu)
{
        static uint64_t general_regs[HV_X86_REGISTERS_MAX];
        uint64_t tmp;

        DPRINTF("------------------------------------------------------------\n");

#define PRINT_REG(name)                                                  \
        hv_rd_reg(vcpu, HV_X86_ ## name, &tmp);                          \
        if (general_regs[HV_X86_ ## name] != tmp) {                      \
                DPRINTF("\033[32;1m%6s: 0x%08llx\033[0m  ", #name, tmp); \
        } else {                                                         \
                DPRINTF("%6s: 0x%08llx  ", #name, tmp);                  \
        }                                                                \
        general_regs[HV_X86_ ## name] = tmp;

        PRINT_REG(RAX);
        PRINT_REG(RBX);
        PRINT_REG(RCX);
        PRINT_REG(RDX);
        DPRINTF("\n");
        PRINT_REG(RDI);
        PRINT_REG(RSI);
        PRINT_REG(RSP);
        PRINT_REG(RBP);
        DPRINTF("\n");
        PRINT_REG(RIP);
        PRINT_REG(RFLAGS);
        PRINT_REG(R8);
        PRINT_REG(R9);
        DPRINTF("\n");
        PRINT_REG(R10);
        PRINT_REG(R11);
        PRINT_REG(R12);
        PRINT_REG(R13);
        DPRINTF("\n");
        PRINT_REG(R14);
        PRINT_REG(R15);
        DPRINTF("\n");
        DPRINTF("------------------------------------------------------------\n");
#undef PRINT_REG
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

void hvf_debug_print_vmexit(uint64_t exit_reason)
{
        DPRINTF("HVF: handling ");
        DPRINTF("\033[33;1m%s\033[0m (0x%llx) exit\n",
                        exit_reason_str(exit_reason & 0xffff),
                        exit_reason & 0xffff);
}

void hvf_debug_print_nmi(uint64_t intr_info)
{
        DPRINTF("  0x%llx:%s:%s:%s\n",
                        intr_info,
                        hvf_debug_interrupt_type(intr_info),
                        ((intr_info >> 11) & 1) ? "VALID" : "INVALID",
                        ((intr_info >> 31) & 1) ? "VALID" : "INVALID");

}

void hvf_debug_print_ept(hv_vcpuid_t vcpu)
{
        uint64_t tmp;
        hv_rd_vmcs(vcpu, VMCS_RO_EXIT_QUALIFIC, &tmp);
        DPRINTF("  %s:%s:%s\n",
                        (tmp & 0x1)
                        ? "Read"
                        : ((tmp & 0x2) == 2)
                        ? "Write"
                        : "Instruction Fetch",
                        ((tmp >> 7) & 0x1)
                        ? "Valid GLA"
                        : "Inalid GLA",
                        ((tmp >> 8) & 0x1)
                        ? "PGA caused"
                        : "Paging structure entry caused");

        hv_rd_vmcs(vcpu, VMCS_GUEST_PHYSICAL_ADDRESS, &tmp);
        DPRINTF("  GPA: %llx\n", tmp);
}

const char *hvf_debug_interrupt_type(uint64_t val)
{
        const char *types[] = {
                "External interrupt",
                "Not used",
                "Non-maskable interrupt (NMI)",
                "Hardware exception",
                "Not used",
                "Not used",
                "Software exception",
                "Not used"
        };

        return types[(val >> 8) & 0x3];
}

void hvf_debug_print_vmcontrols(CPUState *cpu)
{
        uint64_t tmp;

        hv_rd_vmcs(cpu->vcpuid, VMCS_CTRL_VMENTRY_CONTROLS, &tmp);
        print_vmentry_controls(tmp);
        hv_rd_vmcs(cpu->vcpuid, VMCS_CTRL_PIN_BASED, &tmp);
        print_pinbased_controls(tmp);
        hv_rd_vmcs(cpu->vcpuid, VMCS_CTRL_CPU_BASED, &tmp);
        print_procbased1_controls(tmp);
        hv_rd_vmcs(cpu->vcpuid, VMCS_CTRL_CPU_BASED2, &tmp);
        print_procbased2_controls(tmp);
}

void hvf_debug_check_consistency(CPUState *cpu)
{
        CPUX86State *env = &X86_CPU(cpu)->env;
        hv_vcpuid_t vcpu = cpu->vcpuid;

        printf("-- VCPU %d --\n", vcpu);

        uint64_t tmp, ret;

#define check_value(name, vmcs_field)                                       \
        printf("  " #name ":  0x%llx", tmp);                                \
        if (ret) printf("FAILED WITH %llx\n", ret);                         \
        else if (tmp != env->name)                                          \
        printf(" \033[33;1m(should be 0x%llx)\033[0m",                  \
                        (uint64_t) env->name);                                   \
        printf("\n");

#define PRINT_VALUE(name, vmcs_field)                                       \
        ret = hv_rd_vmcs(vcpu, vmcs_field, &tmp);                \
        check_value(name, vmcs_field)

#define PRINT_REG(name, vmcs_field)                                         \
        ret = hv_rd_reg(vcpu, vmcs_field, &tmp);                \
        check_value(name, vmcs_field)

        PRINT_VALUE(segs[R_CS].selector,  VMCS_GUEST_CS);
        PRINT_VALUE(segs[R_CS].base,      VMCS_GUEST_CS_BASE);
        PRINT_VALUE(segs[R_CS].limit,     VMCS_GUEST_CS_LIMIT);
        PRINT_VALUE(segs[R_CS].flags,     VMCS_GUEST_CS_AR);
        PRINT_VALUE(segs[R_DS].selector,  VMCS_GUEST_DS);
        PRINT_VALUE(segs[R_DS].base,      VMCS_GUEST_DS_BASE);
        PRINT_VALUE(segs[R_DS].limit,     VMCS_GUEST_DS_LIMIT);
        PRINT_VALUE(segs[R_DS].flags,     VMCS_GUEST_DS_AR);
        PRINT_VALUE(segs[R_ES].selector,  VMCS_GUEST_ES);
        PRINT_VALUE(segs[R_ES].base,      VMCS_GUEST_ES_BASE);
        PRINT_VALUE(segs[R_ES].limit,     VMCS_GUEST_ES_LIMIT);
        PRINT_VALUE(segs[R_ES].flags,     VMCS_GUEST_ES_AR);
        PRINT_VALUE(segs[R_FS].selector,  VMCS_GUEST_FS);
        PRINT_VALUE(segs[R_FS].base,      VMCS_GUEST_FS_BASE);
        PRINT_VALUE(segs[R_FS].limit,     VMCS_GUEST_FS_LIMIT);
        PRINT_VALUE(segs[R_FS].flags,     VMCS_GUEST_FS_AR);
        PRINT_VALUE(segs[R_GS].selector,  VMCS_GUEST_GS);
        PRINT_VALUE(segs[R_GS].base,      VMCS_GUEST_GS_BASE);
        PRINT_VALUE(segs[R_GS].limit,     VMCS_GUEST_GS_LIMIT);
        PRINT_VALUE(segs[R_GS].flags,     VMCS_GUEST_GS_AR);
        PRINT_VALUE(segs[R_SS].selector,  VMCS_GUEST_SS);
        PRINT_VALUE(segs[R_SS].base,      VMCS_GUEST_SS_BASE);
        PRINT_VALUE(segs[R_SS].limit,     VMCS_GUEST_SS_LIMIT);
        PRINT_VALUE(segs[R_SS].flags,     VMCS_GUEST_SS_AR);
        PRINT_VALUE(idt.base,         VMCS_GUEST_IDTR_BASE);
        PRINT_VALUE(idt.limit,        VMCS_GUEST_IDTR_LIMIT);
        PRINT_VALUE(gdt.base,         VMCS_GUEST_GDTR_BASE);
        PRINT_VALUE(gdt.limit,        VMCS_GUEST_GDTR_LIMIT);
        PRINT_VALUE(ldt.selector,     VMCS_GUEST_LDTR);
        PRINT_VALUE(ldt.base,         VMCS_GUEST_LDTR_BASE);
        PRINT_VALUE(ldt.limit,        VMCS_GUEST_LDTR_LIMIT);
        PRINT_VALUE(ldt.flags,        VMCS_GUEST_LDTR_AR);
        PRINT_VALUE(tr.selector,      VMCS_GUEST_TR);
        PRINT_VALUE(tr.base,          VMCS_GUEST_TR_BASE);
        PRINT_VALUE(tr.limit,         VMCS_GUEST_TR_LIMIT);
        PRINT_VALUE(tr.flags,         VMCS_GUEST_TR_AR);
        PRINT_VALUE(cr[0],            VMCS_GUEST_CR0);
        PRINT_VALUE(cr[3],            VMCS_GUEST_CR3);
        PRINT_VALUE(cr[4],            VMCS_GUEST_CR4);
        PRINT_VALUE(efer,             VMCS_GUEST_IA32_EFER);

        PRINT_REG(eip,         HV_X86_RIP);
        PRINT_REG(eflags,      HV_X86_RFLAGS);
        PRINT_REG(regs[R_EAX], HV_X86_RAX);
        PRINT_REG(regs[R_EBX], HV_X86_RBX);
        PRINT_REG(regs[R_ECX], HV_X86_RCX);
        PRINT_REG(regs[R_EDX], HV_X86_RDX);
        PRINT_REG(regs[R_ESI], HV_X86_RSI);
        PRINT_REG(regs[R_EDI], HV_X86_RDI);
        PRINT_REG(regs[R_ESP], HV_X86_RSP);
        PRINT_REG(regs[R_EBP], HV_X86_RBP);
        PRINT_REG(regs[8],     HV_X86_R8);
        PRINT_REG(regs[9],     HV_X86_R9);
        PRINT_REG(regs[10],    HV_X86_R10);
        PRINT_REG(regs[11],    HV_X86_R11);
        PRINT_REG(regs[12],    HV_X86_R12);
        PRINT_REG(regs[13],    HV_X86_R13);
        PRINT_REG(regs[14],    HV_X86_R14);
        PRINT_REG(regs[15],    HV_X86_R15);
        PRINT_REG(dr[0],       HV_X86_DR0);
        PRINT_REG(dr[1],       HV_X86_DR1);
        PRINT_REG(dr[2],       HV_X86_DR2);
        PRINT_REG(dr[3],       HV_X86_DR3);
        PRINT_REG(dr[4],       HV_X86_DR4);
        PRINT_REG(dr[5],       HV_X86_DR5);
        PRINT_REG(dr[6],       HV_X86_DR6);
        PRINT_REG(dr[7],       HV_X86_DR7);

        printf("--       --\n");



}

void hvf_debug_check_vm_entry(CPUState *cpu)
{
#define GET_AND_CHECK_VMCS(val, var) \
        var = 0;\
        ret = hv_rd_vmcs(vcpuid, val, &var); \
        if (ret) {printf("\033[31;1mREADING VMCS FAILED FOR " #val " (0x%x)\033[0m\n", ret); abort();}

#define GET_AND_CHECK_MSR(val, var) \
        var = 0;\
        ret = hv_vcpu_read_msr(vcpuid, val, &var); \
        if (ret) {printf("\033[31;1mREADING MSR FAILED FOR " #val " (0x%x)\033[0m\n", ret); abort();}

#define warning(str) printf("\033[33;1m[*] %s\033[0m", str);
        printf("\033[31;1mCHECKING CPU STATE FOR VMENTRY\033[0m\n");

        hv_return_t ret = 0;
        hv_vcpuid_t vcpuid = cpu->vcpuid;

        uint64_t tmp, tmp2;
        uint64_t controls, pin_based, cpu_based1, cpu_based2, interrupt;
        uint64_t cr0, cr4, rflags, rip;
        uint8_t unrestricted_guest, load_debug_controls, ia_32e_mode_guest,
                ia_32_perf_global_ctrl, ia_32_pat, ia_32_efer, ia_32_bndcfgs,
                v8086, valid;


        GET_AND_CHECK_VMCS(VMCS_CTRL_VMENTRY_CONTROLS, controls);
        GET_AND_CHECK_VMCS(VMCS_CTRL_PIN_BASED, pin_based);
        GET_AND_CHECK_VMCS(VMCS_CTRL_CPU_BASED, cpu_based1);
        GET_AND_CHECK_VMCS(VMCS_CTRL_CPU_BASED2, cpu_based2);
        GET_AND_CHECK_VMCS(VMCS_CTRL_VMENTRY_IRQ_INFO, interrupt);
        GET_AND_CHECK_VMCS(VMCS_GUEST_CR0, cr0);
        GET_AND_CHECK_VMCS(VMCS_GUEST_CR4, cr4);
        GET_AND_CHECK_VMCS(VMCS_GUEST_RFLAGS, rflags);
        GET_AND_CHECK_VMCS(VMCS_GUEST_RIP, rip);

        unrestricted_guest          = get_bit(cpu_based2, 7);
        load_debug_controls         = get_bit(controls, 2);
        ia_32e_mode_guest           = get_bit(controls, 9);
        ia_32_perf_global_ctrl      = get_bit(controls, 13);
        ia_32_pat                   = get_bit(controls, 14);
        ia_32_efer                  = get_bit(controls, 15);
        ia_32_bndcfgs               = get_bit(controls, 16);
        valid                       = get_bit(interrupt, 31);
        v8086                       = get_bit(rflags, 17);


        if (!unrestricted_guest) {
                assert(!get_bit(cr0, 31) || get_bit(cr0, 0));
        }

        if (load_debug_controls) {
                GET_AND_CHECK_VMCS(VMCS_GUEST_IA32_DEBUGCTL, tmp);
                hv_wr_vmcs(vcpuid, VMCS_GUEST_IA32_DEBUGCTL, tmp & 0b1101111111000011);
                GET_AND_CHECK_VMCS(VMCS_GUEST_IA32_DEBUGCTL, tmp);
                assert(!get_bit(tmp, 2)
                                && !get_bit(tmp, 3)
                                && !get_bit(tmp, 4)
                                && !get_bit(tmp, 5)
                                && !get_bit(tmp, 13)
                                && tmp < 65535);
        }

        if (ia_32e_mode_guest) {
                assert(get_bit(cr0, 31) && get_bit(cr4, 5));
        } else {
                assert(!get_bit(cr4, 17));
        }

        GET_AND_CHECK_VMCS(VMCS_GUEST_CR3, tmp);
        assert(!tmp); // CR3 field must be such that bits 63:52 and
        // bits in the range 51:32 beyond the
        // processor's physical address width are 0

        if (load_debug_controls) {
                GET_AND_CHECK_VMCS(VMCS_GUEST_DR7, tmp);
                assert(tmp < 0b100000000000000000000000000000000);
        }

        if (ia_32_perf_global_ctrl) {
                warning("IA_32_PERF_GLOBAL_CTRL not tested\n");
                GET_AND_CHECK_VMCS(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL, tmp);
                assert(!tmp); // Too few bits not reserved
        }

        if (ia_32_pat) {
                warning("IA_32_PAT not tested\n");
                GET_AND_CHECK_VMCS(VMCS_GUEST_IA32_PAT, tmp);
                for (int i = 0; i < 8; ++i) {
                        char tmpbyte = tmp & 0xff;
                        assert(tmpbyte == 0
                                        || tmpbyte == 1
                                        || tmpbyte == 4
                                        || tmpbyte == 5
                                        || tmpbyte == 6
                                        || tmpbyte == 7);
                        tmp >>= 8;

                }
        }

        if (ia_32_efer) {
                GET_AND_CHECK_VMCS(VMCS_GUEST_IA32_EFER, tmp);
                assert(!tmp); // Too few bits not reserved
                assert(get_bit(tmp, 10) == ia_32e_mode_guest);
                assert(!get_bit(cr0, 31) || (get_bit(tmp, 10) == get_bit(tmp, 8)));
        }

        if (ia_32_bndcfgs) {
                warning("Didn't check IA32_BNDCFGS\n")
        }


        GET_AND_CHECK_VMCS(VMCS_GUEST_TR, tmp);
        assert(!get_bit(tmp, 2));
        GET_AND_CHECK_VMCS(VMCS_GUEST_LDTR, tmp);
        assert(!get_bit(tmp, 2));

        if (!v8086 && !unrestricted_guest) {
                GET_AND_CHECK_VMCS(VMCS_GUEST_SS, tmp);
                GET_AND_CHECK_VMCS(VMCS_GUEST_CS, tmp2);
                assert((tmp & 0x3) == (tmp2 & 0x3));
        }

        if (v8086) {
                warning("v8086 not tested\n");
#define v8086_SEGMENT_BASE_CHECKS(SEGMENT)\
                GET_AND_CHECK_VMCS(VMCS_GUEST_ ## SEGMENT, tmp);\
                GET_AND_CHECK_VMCS(VMCS_GUEST_ ## SEGMENT ## _BASE, tmp2);\
                assert(tmp2 == (tmp << 4));

                v8086_SEGMENT_BASE_CHECKS(CS);
                v8086_SEGMENT_BASE_CHECKS(SS);
                v8086_SEGMENT_BASE_CHECKS(DS);
                v8086_SEGMENT_BASE_CHECKS(ES);
                v8086_SEGMENT_BASE_CHECKS(FS);
                v8086_SEGMENT_BASE_CHECKS(GS);
        }

#define IA32E_SEGMENT_BASE_CHECKS(SEGMENT)\
        GET_AND_CHECK_VMCS(VMCS_GUEST_## SEGMENT ##_BASE, tmp);\
        assert(tmp < 0b100000000000000000000000000000000);
        IA32E_SEGMENT_BASE_CHECKS(CS);
        IA32E_SEGMENT_BASE_CHECKS(SS);
        IA32E_SEGMENT_BASE_CHECKS(DS);
        IA32E_SEGMENT_BASE_CHECKS(ES);

        if (v8086) {
#define v8086_SEGMENT_LIMIT_CHECKS(SEGMENT)\
                GET_AND_CHECK_VMCS(VMCS_GUEST_ ## SEGMENT ## _LIMIT, tmp);\
                assert(tmp == 0x0000ffff);
                v8086_SEGMENT_LIMIT_CHECKS(CS);
                v8086_SEGMENT_LIMIT_CHECKS(SS);
                v8086_SEGMENT_LIMIT_CHECKS(DS);
                v8086_SEGMENT_LIMIT_CHECKS(ES);
                v8086_SEGMENT_LIMIT_CHECKS(FS);
                v8086_SEGMENT_LIMIT_CHECKS(GS);

#define v8086_SEGMENT_AR_CHECKS(SEGMENT)\
                GET_AND_CHECK_VMCS(VMCS_GUEST_ ## SEGMENT ## _AR, tmp);\
                assert(tmp == 0xf3);
                v8086_SEGMENT_AR_CHECKS(CS);
                v8086_SEGMENT_AR_CHECKS(SS);
                v8086_SEGMENT_AR_CHECKS(DS);
                v8086_SEGMENT_AR_CHECKS(ES);
                v8086_SEGMENT_AR_CHECKS(FS);
                v8086_SEGMENT_AR_CHECKS(GS);
        } else {
                // CS
                GET_AND_CHECK_VMCS(VMCS_GUEST_CS_AR, tmp);
                tmp &= 0xf;
                if (!unrestricted_guest) {
                        // 9, 11, 13 or 15
                        assert(get_bit(tmp, 0) && get_bit(tmp, 3));
                } else {
                        // 3, 9, 11, 13 or 15
                        assert((get_bit(tmp, 0) && get_bit(tmp, 3)) || tmp == 3);
                }

                // SS
                GET_AND_CHECK_VMCS(VMCS_GUEST_SS_AR, tmp);
                tmp &= 0xf;
                assert((tmp == 3) || (tmp == 7));

                // DS, ES, FS, GS
#define SEGMENT_AR_CHECKS(SEGMENT)\
                GET_AND_CHECK_VMCS(VMCS_GUEST_ ## SEGMENT ## _AR, tmp);\
                assert(get_bit(tmp, 0) && (!get_bit(tmp, 3) || get_bit(tmp, 1)));
                SEGMENT_AR_CHECKS(DS);
                SEGMENT_AR_CHECKS(ES);
                SEGMENT_AR_CHECKS(FS);
                SEGMENT_AR_CHECKS(GS);

                GET_AND_CHECK_VMCS(VMCS_GUEST_CS_AR, tmp);
                assert(get_bit(tmp, 4));

                // CS DPL
                GET_AND_CHECK_VMCS(VMCS_GUEST_SS_AR, tmp2);
                uint8_t type = tmp & 0xf;
                uint8_t cs_dpl = (tmp & 0x30) >> 4;
                uint8_t ss_dpl = (tmp2 & 0x30) >> 4;
                switch (type) {
                        case 3:
                                assert(!cs_dpl && unrestricted_guest);
                                break;
                        case 9:
                        case 11:
                                assert(cs_dpl == ss_dpl);
                                break;
                        case 13:
                        case 15:
                                assert(cs_dpl <= ss_dpl);
                                break;
                        default:
                                warning("Invalid type for CS\n");
                                abort();
                }

                // SS DPL
                warning("Didn't check SS RPL\n");
                assert(ss_dpl || (((tmp2 & 0xf) == 3) || (!get_bit(cr0, 0))));

                // DS, ES, FS, GS DPLs
                warning("Didn't check DS, ES, FS, GS DPLs\n");


                GET_AND_CHECK_VMCS(VMCS_GUEST_CS_AR, tmp);
                assert(get_bit(tmp, 7));
                assert(!get_bit(tmp, 8));
                assert(!get_bit(tmp, 9));
                assert(!get_bit(tmp, 10));
                assert(!get_bit(tmp, 11));

                if (ia_32e_mode_guest && get_bit(13, tmp)) {
                        assert(!get_bit(tmp, 14));
                }

                GET_AND_CHECK_VMCS(VMCS_GUEST_CS_LIMIT, tmp2);
                if ((tmp2 & 0xfff) != 0xfff) {
                        assert(!get_bit(tmp, 15));
                }
                if (tmp2 > 0xfffff) {
                        assert(get_bit(tmp, 15));
                }

                for (int i = 16; i < 32; ++i) {
                        assert(!get_bit(tmp, i)); // I don't care anymore.
                }

        }

        // TR AR
        GET_AND_CHECK_VMCS(VMCS_GUEST_TR_AR, tmp);
        GET_AND_CHECK_VMCS(VMCS_GUEST_TR_LIMIT, tmp2);
        uint8_t tr_type = tmp & 0xf;
        assert(tr_type == 11 || (tr_type == 3 && !ia_32e_mode_guest));
        assert(!get_bit(tmp, 4));
        assert(get_bit(tmp, 7));
        assert(!get_bit(tmp, 8));
        assert(!get_bit(tmp, 9));
        assert(!get_bit(tmp, 10));
        assert(!get_bit(tmp, 11));

        if ((tmp2 & 0xfff) != 0xfff) {
                assert(!get_bit(tmp, 15));
        }
        if (tmp2 > 0xfffff) {
                assert(get_bit(tmp, 15));
        }

        for (int i = 16; i < 32; ++i) {
                assert(!get_bit(tmp, i)); // I still don't care.
        }

        // LDTR AR
        GET_AND_CHECK_VMCS(VMCS_GUEST_LDTR_AR, tmp);
        GET_AND_CHECK_VMCS(VMCS_GUEST_LDTR_LIMIT, tmp2);
        //assert(tmp & 0xf == 2); // USELESS
        assert(!get_bit(tmp, 4));
        //assert(get_bit(tmp, 7));  // USELESS
        assert(!get_bit(tmp, 8));
        assert(!get_bit(tmp, 9));
        assert(!get_bit(tmp, 10));
        assert(!get_bit(tmp, 11));

        if ((tmp2 & 0xfff) != 0xfff) {
                assert(!get_bit(tmp, 15));
        }
        if (tmp2 > 0xfffff) {
                assert(get_bit(tmp, 15));
        }

        for (int i = 16; i < 32; ++i) {
                //assert(!get_bit(tmp, i)); // USELESS
        }

        GET_AND_CHECK_VMCS(VMCS_GUEST_GDTR_LIMIT, tmp);
        assert(tmp < 0b100000000000000000000000000000000);
        GET_AND_CHECK_VMCS(VMCS_GUEST_IDTR_LIMIT, tmp);
        assert(tmp < 0b100000000000000000000000000000000);

        if (!ia_32e_mode_guest || !get_bit(tmp, 13)) {
                assert(rip < 0b100000000000000000000000000000000);
        }

        warning("Didn't check 26.3.1.4.RIP.2\n");

        assert(rflags < 0b100000000000000000000);
        //assert(!get_bit(rflags, 15) && !get_bit(rflags, 5) && !get_bit(rflags, 3) && get_bit(rflags, 1)); // USELESS
        if (ia_32e_mode_guest || !get_bit(cr0, 0)) {
                assert(!get_bit(rflags, 17));
        }
        assert(!get_bit(rflags, 17) || (!ia_32e_mode_guest && get_bit(cr0, 0)));

        uint8_t irq_type = (interrupt >> 8) & 3;
        assert(get_bit(rflags, 9) || (!valid || irq_type != IRQ_INFO_EXT_IRQ));

        warning("Didn't check 26.3.1.5.1\n");
        GET_AND_CHECK_VMCS(VMCS_GUEST_INT_STATUS, tmp);
        assert(tmp < 0x20);
        //assert(!(get_bit(tmp, 0) && get_bit(tmp, 1)));
        //assert(!get_bit(tmp, 0) || get_bit(rflags, 9));
        assert(!get_bit(tmp, 0) || (!valid || irq_type != (IRQ_INFO_EXT_IRQ >> 8)));
        assert(!get_bit(tmp, 1) || (!valid || irq_type != (IRQ_INFO_EXT_IRQ >> 8)));
        assert(!get_bit(tmp, 1) || (!valid || irq_type != (IRQ_INFO_NMI >> 8)));
        assert(get_bit(tmp, 2) == get_bit(controls, 10));
        assert(!get_bit(tmp, 0) || (!valid || irq_type != (IRQ_INFO_NMI >> 8))); // Maybe
        assert(!get_bit(tmp, 3) || !(get_bit(pin_based, 5) && valid && irq_type == (IRQ_INFO_NMI >> 8)));
        warning("Didn't check Enclave/SGX part of interruptibility state\n");


        GET_AND_CHECK_VMCS(VMCS_GUEST_DEBUG_EXC, tmp);
        assert(tmp <= 0b11111111111111111
                        && !get_bit(tmp, 15)
                        && !get_bit(tmp, 13)
                        && !get_bit(tmp, 11)
                        && !get_bit(tmp, 10)
                        && !get_bit(tmp, 9)
                        && !get_bit(tmp, 8)
                        && !get_bit(tmp, 7)
                        && !get_bit(tmp, 6)
                        && !get_bit(tmp, 5)
                        && !get_bit(tmp, 4));

        if (/* SOME STUFF */ 1) {
                GET_AND_CHECK_VMCS(VMCS_GUEST_IA32_DEBUGCTL, tmp2);
                assert(get_bit(tmp, 14 || !(get_bit(rflags, 8) && !get_bit(tmp2, 1))));
        }

        if (get_bit(tmp, 16)) {
                warning("VMCS_GUEST_DEBUG_EXC[16] not tested\n");
                for (int i = 0; i < 16; ++i) {
                        if (i != 12) {
                                assert(!get_bit(tmp, i));
                        }
                }

                warning("Didn't check CPUID part (VMCS_GUEST_DEBUG_EXC)\n");
                GET_AND_CHECK_VMCS(VMCS_GUEST_INT_STATUS, tmp);
                assert(!get_bit(tmp, 1));
        }


        GET_AND_CHECK_VMCS(VMCS_GUEST_LINK_POINTER, tmp);
        if (tmp != 0xffffffffffffffff) {
                warning("VMCS_GUEST_LINK_POINTER's value is ");
                printf("%llx\n", tmp);
                warning("VMCS_GUEST_LINK_POINTER not tested\n");
                for (int i = 0; i < 12; ++i) {
                        //assert(!get_bit(tmp, i));
                }

        }

        GET_AND_CHECK_VMCS(VMCS_GUEST_IA32_EFER, tmp);
        if (get_bit(cr0, 31) && get_bit(cr4, 5) && !get_bit(controls, 9)) {
                warning("PAE not tested\n");
        }


        printf("\033[32;1mEVERYTHING CLEAR SO FAR\033[0m\n");

}
