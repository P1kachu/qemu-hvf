#include "qemu/osdep.h"

#include <Hypervisor/hv.h>

//#include "sysemu/kvm.h"
#include "cpu.h"

#include "exec/address-spaces.h"
#include "exec/memory.h"
#include "sysemu/hvf.h"

MemoryListener memory_listener;

static void hvf_region_add(MemoryListener *listener,
                           MemoryRegionSection *section)
{

        memory_region_ref(section->mr);
        MemoryRegion *mr = section->mr;
        uint64_t flags = 0;
        uint64_t size = int128_get64(section->size);
        uint64_t start_addr = section->offset_within_address_space;
        uint64_t delta = qemu_real_host_page_size - (start_addr & ~qemu_real_host_page_mask);
        delta &= ~qemu_real_host_page_mask;

        if (delta > size) {
                return;
        }

        start_addr += delta;
        size -= delta;
        size &= qemu_real_host_page_mask;

        if (!size || (start_addr & ~qemu_real_host_page_mask)) {
                return;
        }

        if (!memory_region_is_ram(mr)) {
                if (!mr->readonly && !mr->rom_device) {
                        return;
                }
        }

        flags = HV_MEMORY_WRITE | HV_MEMORY_READ | HV_MEMORY_EXEC;

        void *ram = memory_region_get_ram_ptr(mr) + section->offset_within_region + delta;

        // TODO: Correct access rights (exploitation heaven right now)
        hv_return_t ret;
        ret = hv_vm_map(ram, start_addr, size, flags);
        DPRINTF("HVF: \033[32;1mhvf_region_add\033[0m(0x%016llx - 0x%016llx) - ram: %lx - flags: %x ",
                        start_addr, start_addr + size, (uint64_t)ram, flags);
        DPRINTF(" = %x\n", ret);
}

static void hvf_region_del(MemoryListener *listener,
                           MemoryRegionSection *section)
{
        uint64_t size = int128_get64(section->size);
        uint64_t start_addr = section->offset_within_address_space;
        DPRINTF("HVF: \033[31;1mhvf_region_del\033[0m(0x%016llx - 0x%016llx)\n", start_addr, size + start_addr);
}

hv_return_t hvf_memory_init(MachineState *ms)
{
        DPRINTF("HVF: hvf_memory_init\n");

        memory_listener.region_add = hvf_region_add;
        memory_listener.region_del = hvf_region_del;

        memory_listener_register(&memory_listener, &address_space_memory);

        return 0;
}



