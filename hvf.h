#ifndef HVF_H
#define HVF_H

#include "qom/cpu.h"

typedef struct HVFState {
} HVFState;

extern bool hvf_allowed;

#ifdef CONFIG_HVF

# include <Hypervisor/hv.h>
# include <Hypervisor/hv_vmx.h>
# include <Hypervisor/hv_arch_vmx.h>

# define TYPE_HVF_ACCEL ACCEL_CLASS_NAME("hvf")
# define hvf_enabled() (hvf_allowed)

hv_return_t hvf_vcpu_exec(CPUState *cpu);
hv_return_t hvf_vcpu_init(CPUState *cpu);

#else

# define hvf_enabled() (0)

#endif /* CONFIG_HVF */

#endif /* HVF_H */
