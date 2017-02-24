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

/*
 * Parsing Intel manual to understand why I
 * get this fuc**** VMX_REASON_VMENTRY_GUEST
 * error.
 */

#define GET_AND_CHECK_VMCS(val, var) \
        var = 0;\
        ret = hv_vmx_vcpu_read_vmcs(vcpuid, val, &var); \
        if (ret) {printf("\033[31;1mREADING VMCS FAILED FOR " #val " (0x%x)\033[0m\n", ret); abort();}

#define GET_AND_CHECK_MSR(val, var) \
        var = 0;\
        ret = hv_vcpu_read_msr(vcpuid, val, &var); \
        if (ret) {printf("\033[31;1mREADING MSR FAILED FOR " #val " (0x%x)\033[0m\n", ret); abort();}

#define warning(str) printf("\033[33;1m[*] %s\033[0m", str);
static void check_vm_entry(CPUState *cpu)
{
        printf("\033[31;1mCHECKING CPU STATE FOR VMENTRY\033[0m\n");

        hv_return_t ret = 0;
        hv_vcpuid_t vcpuid = cpu->vcpuid;

        uint64_t tmp, tmp2;
        uint64_t controls, pin_based, cpu_based1, cpu_based2;
        uint64_t cr0, cr4, rflags;
        uint8_t unrestricted_guest, load_debug_controls, ia_32e_mode_guest,
                ia_32_perf_global_ctrl, ia_32_pat, ia_32_efer, ia_32_bndcfgs,
                v8086;


        GET_AND_CHECK_VMCS(VMCS_CTRL_VMENTRY_CONTROLS, controls);
        GET_AND_CHECK_VMCS(VMCS_CTRL_PIN_BASED, pin_based);
        GET_AND_CHECK_VMCS(VMCS_CTRL_CPU_BASED, cpu_based1);
        GET_AND_CHECK_VMCS(VMCS_CTRL_CPU_BASED2, cpu_based2);
        GET_AND_CHECK_VMCS(VMCS_GUEST_CR0, cr0);
        GET_AND_CHECK_VMCS(VMCS_GUEST_CR4, cr4);
        GET_AND_CHECK_VMCS(VMCS_GUEST_RFLAGS, rflags);

        unrestricted_guest      = get_bit(cpu_based2, 7);
        load_debug_controls     = get_bit(controls, 2);
        ia_32e_mode_guest       = get_bit(controls, 9);
        ia_32_perf_global_ctrl  = get_bit(controls, 13);
        ia_32_pat               = get_bit(controls, 14);
        ia_32_efer              = get_bit(controls, 15);
        ia_32_bndcfgs           = get_bit(controls, 16);
        v8086                   = get_bit(rflags, 17);


        if (!unrestricted_guest) {
                assert(!get_bit(cr0, 31) || get_bit(cr0, 0));
        }

        if (load_debug_controls) {
                GET_AND_CHECK_VMCS(VMCS_GUEST_IA32_DEBUGCTL, tmp);
                hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_IA32_DEBUGCTL, tmp & 0b1101111111000011);
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

        warning("Didn't check IA32_SYSENTER_ESP canonical\n");
        warning("Didn't check IA32_SYSENTER_EIP canonical\n");


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

        warning("Didn't check TR, FS, GS, LDTR base address canonical\n");

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

        }

        printf("\033[32;1mEVERYTHING CLEAR SO FAR\033[0m\n");

}

void hvf_debug(CPUState *cpu)
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
        ret = hv_vmx_vcpu_read_vmcs(vcpu, vmcs_field, &tmp);                \
        check_value(name, vmcs_field)

#define PRINT_REG(name, vmcs_field)                                         \
        ret = hv_vcpu_read_register(vcpu, vmcs_field, &tmp);                \
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

       check_vm_entry(cpu);


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

        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_IA32_SYSENTER_CS, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_IA32_SYSENTER_EIP, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_IA32_SYSENTER_ESP, HVF_MSR_ENABLE);

        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_SYSENTER_EIP, env->sysenter_eip);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_SYSENTER_ESP, env->sysenter_esp);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_IA32_SYSENTER_CS, env->sysenter_cs);
        ret |= hv_vmx_vcpu_write_vmcs(vcpuid, VMCS_GUEST_IA32_EFER, env->efer);

#ifdef TARGET_X86_64
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_KERNELGSBASE, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_FMASK, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_LSTAR, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_CSTAR, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_STAR, HVF_MSR_ENABLE);
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

#if 1   // DEBUG

        uint64_t tmp;
        hv_vmx_vcpu_read_vmcs(cpu->vcpuid, VMCS_CTRL_VMENTRY_CONTROLS, &tmp);
        print_vmentry_controls(tmp);
        hv_vmx_vcpu_read_vmcs(cpu->vcpuid, VMCS_CTRL_PIN_BASED, &tmp);
        print_pinbased_controls(tmp);
        hv_vmx_vcpu_read_vmcs(cpu->vcpuid, VMCS_CTRL_CPU_BASED, &tmp);
        print_procbased1_controls(tmp);
        hv_vmx_vcpu_read_vmcs(cpu->vcpuid, VMCS_CTRL_CPU_BASED2, &tmp);
        print_procbased2_controls(tmp);
#endif


#if 0   // DEBUG
        // TSC ?
        hv_return_t vcpuid = cpu->vcpuid;
        // Need to check why
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_GSBASE, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_FSBASE, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_IA32_TSC, HVF_MSR_ENABLE);
        ret |= hv_vcpu_enable_native_msr(vcpuid, MSR_TSC_AUX, HVF_MSR_ENABLE);

#endif
		return ret;
}

