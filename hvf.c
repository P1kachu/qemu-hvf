#include "qemu/osdep.h"

#include <Hypervisor/hv.h>

#include "sysemu/accel.h"
#include "qemu/module.h"
#include "hvf.h"

bool hvf_allowed = true;

static int hvf_init(MachineState *ms)
{
        printf("HVF: Init\n");
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
