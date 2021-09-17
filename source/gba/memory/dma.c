/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "gba/gba.h"
#include "gba/scheduler.h"

static uint32_t src_mask[4]   = {0x07FFFFFF, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF};
static uint32_t dst_mask[4]   = {0x07FFFFFF, 0x07FFFFFF, 0x07FFFFFF, 0x0FFFFFFF};
static uint32_t count_mask[4] = {0x3FFF,     0x3FFF,     0x3FFF,     0xFFFF};

void
mem_dma_load(
    struct dma_channel *channel,
    uint32_t channel_idx
) {
    channel->internal_src = channel->src.raw & (channel->control.unit_size ? ~3 : ~1); // TODO Investigate why the alignment is needed
    channel->internal_src &= src_mask[channel_idx];
    channel->internal_dst = channel->dst.raw & (channel->control.unit_size ? ~3 : ~1); // TODO Investigate why the alignment is needed
    channel->internal_dst &= dst_mask[channel_idx];
    channel->internal_count = channel->count.raw;
    channel->internal_count &= count_mask[channel_idx];
}

/*
** Go through all DMA channels and process them (if they are enabled).
*/
static
void
mem_do_dma_transfer(
    struct gba *gba,
    union event_data data
) {
    enum dma_timings timing;
    size_t i;
    bool prefetch_state;

    /*
    ** Disable prefetchng during DMA.
    **
    ** According to Fleroviux (https://github.com/fleroviux/) this
    ** leads to better accuracy but the reasons why aren't well known yet.
    */
    prefetch_state = gba->memory.pbuffer.enabled;
    gba->memory.pbuffer.enabled = false;

    timing = data.u32;
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
            channel->internal_count = count_mask[i] + 1;
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
            channel->internal_count &= count_mask[i];
            if (reload) {
                channel->internal_dst = channel->dst.raw & (channel->control.unit_size ? ~3 : ~1);
                channel->internal_dst &= dst_mask[i];
            }
        } else {
            channel->control.enable = false;
        }
    }
    gba->memory.pbuffer.enabled = prefetch_state;
}

void
mem_schedule_dma_transfer(
    struct gba *gba,
    enum dma_timings timing
) {
    sched_add_event(
        gba,
        NEW_FIX_EVENT_DATA(
            gba->core.cycles + 3,
            mem_do_dma_transfer,
            (union event_data){ .u32 = timing }
        )
    );
}