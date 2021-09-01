/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "gba.h"

void
mem_dma_load(
    struct dma_channel *channel,
    uint32_t channel_idx
) {
    channel->internal_src = channel->src.raw & (channel->control.unit_size ? ~3 : ~1); // TODO Investigate why the alignment is needed
    channel->internal_src &= channel_idx ? 0x0FFFFFFF : 0x07FFFFFF;
    channel->internal_dst = channel->dst.raw & (channel->control.unit_size ? ~3 : ~1); // TODO Investigate why the alignment is needed
    channel->internal_dst &= (channel_idx != 3) ? 0x0FFFFFFF : 0x07FFFFFF;
    channel->internal_count = channel->count.raw;
}

/*
** Go through all DMA channels and process them (if they are enabled).
*/
void
mem_dma_transfer(
    struct gba *gba,
    enum dma_timings timing
) {
    size_t i;
    bool prefetch_enabled;

    /*
    ** Disable prefetchng during DMA.
    **
    ** According to Fleroviux (https://github.com/fleroviux/) this
    ** leads to better accuracy but the reasons why aren't well known.
    */
    prefetch_enabled = gba->memory.pbuffer.enabled;
    gba->memory.pbuffer.enabled = false;

    for (i = 0; i < 4; ++i) {
        struct dma_channel *channel;
        enum access_type access;
        int32_t src_step;
        int32_t dst_step;
        int32_t unit_size;
        bool reload;

        channel = &gba->io.dma[i];

        // Skip channels that aren't enabled or that shouldn't happen at the given timing
        if (!channel->control.enable || channel->control.timing != timing) {
            continue;
        }

        // All DMA take at least two internal cycles.
        core_idle_for(gba, 2);

        // If both source and destination are in gamepak memory area, the DMA takes
        // two more internal cycles.
        if (   ((channel->internal_src >> 24) & 0xF) >= CART_REGION_START
            && ((channel->internal_src >> 24) & 0xF) <= CART_REGION_END
            && ((channel->internal_dst >> 24) & 0xF) >= CART_REGION_START
            && ((channel->internal_dst >> 24) & 0xF) <= CART_REGION_END
        ) {
            core_idle_for(gba, 2);
        }

        reload = false;
        unit_size = channel->control.unit_size ? 4 : 2; // In  bytes

        switch (channel->control.dst_ctl) {
            case 0b00:      dst_step = unit_size; break;
            case 0b01:      dst_step = -unit_size; break;
            case 0b10:      dst_step = 0; break;
            case 0b11:      dst_step = unit_size; reload = true; break;
        }

        switch (channel->control.src_ctl) {
            case 0b00:      src_step = unit_size; break;
            case 0b01:      src_step = -unit_size; break;
            case 0b10:      src_step = 0; break;
            case 0b11:      src_step = 0; break;
        }

        // A count of 0 is treated as max length.
        if (channel->internal_count == 0) {
            channel->internal_count = (i == 3 ? 0x10000 : 0x4000);
        }

        logln(
            HS_DMA,
            "DMA transfer from 0x%08x%c to 0x%08x%c (len=%#08x, unit_size=%u, channel %zu)",
            channel->internal_src,
            src_step > 0 ? '+' : '-',
            channel->internal_dst,
            dst_step > 0 ? '+' : '-',
            channel->internal_count,
            unit_size,
            i
        );

        if (channel->internal_dst == 0x040000A0 || channel->internal_dst == 0x040000A4) {
            logln(HS_DMA, "FIFO transfer -- Ignored");
        } else {
            access = NON_SEQUENTIAL;
            while (channel->internal_count > 0) {
                if (unit_size == 4) {
                    mem_write32(gba, channel->internal_dst, mem_read32(gba, channel->internal_src, access), access);
                } else { // unit_size == 2
                    mem_write16(gba, channel->internal_dst, mem_read16(gba, channel->internal_src, access), access);
                }
                channel->internal_src += src_step;
                channel->internal_dst += dst_step;
                channel->internal_count -= 1;
                access = SEQUENTIAL;
            }
        }

        if (channel->control.irq_end) {
            core_trigger_irq(gba, IRQ_DMA0 + i);
        }

        if (channel->control.repeat) {
            channel->internal_count = channel->count.raw;
            if (reload) {
                channel->internal_dst = channel->dst.raw & (channel->control.unit_size ? ~3 : ~1);
                channel->internal_dst &= (i != 3) ? 0x0FFFFFFF : 0x07FFFFFF;
            }
        } else {
            channel->control.enable = false;
        }
    }
    gba->memory.pbuffer.enabled = prefetch_enabled;
}