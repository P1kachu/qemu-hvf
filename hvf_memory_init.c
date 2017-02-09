#include "qemu/osdep.h"

#include <Hypervisor/hv.h>

#include "exec/memory.h"
#include "exec/address-spaces.h"
#include "sysemu/hvf.h"

MemoryListener memory_listener;

static void hvf_region_add(MemoryListener *listener,
                           MemoryRegionSection *section)
{
        uint64_t size = int128_get64(section->size);
        uint64_t start_addr = section->offset_within_address_space;
        DPRINTF("HVF: hvf_region_add(0x%llx bytes at 0x%llx)\n", size, start_addr);

        void *vm_mem = g_malloc0(size);

        if (!vm_mem) {
                fprintf(stderr, "HVF: Memory zone allocation failed in hv_region_add\n");
                exit(1);
        }

        // TODO: Correct access rights (exploitation heaven right now)
        hv_vm_map(vm_mem, start_addr, size, HV_MEMORY_WRITE | HV_MEMORY_READ | HV_MEMORY_EXEC);
}

static void hvf_region_del(MemoryListener *listener,
                           MemoryRegionSection *section)
{
        DPRINTF("HVF: hvf_region_delete\n");
}

hv_return_t hvf_memory_init(MachineState *ms)
{
        DPRINTF("HVF: hvf_memory_init\n");

        memory_listener.region_add = hvf_region_add;
        memory_listener.region_del = hvf_region_del;

        memory_listener_register(&memory_listener, &address_space_memory);

        return 0;
}



