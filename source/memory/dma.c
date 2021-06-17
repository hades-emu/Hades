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

/*
** Go through all DMA channels and process them (if they are enabled).
*/
void
mem_dma_transfer(
    struct gba *gba,
    enum dma_timings timing
) {
    size_t i;

    for (i = 0; i < 4; ++i) {
        struct dma_channel *channel;
        uint32_t src;
        int32_t src_step;
        uint32_t dst;
        int32_t dst_step;
        uint32_t count;
        int32_t unit_size;

        channel = &gba->io.dma[i];

        if (channel->control.enable && channel->control.timing == 3) {
            logln(HS_WARNING, "Unsupported special timing for DMA request");
        }

        // Skip channels that aren't enabled or that shouldn't happen at the given timing
        if (!channel->control.enable || channel->control.timing != timing) {
            continue;
        }

        src = channel->src.raw & (channel->control.unit_size ? ~3 : ~1); // TODO Investigate why the alignment is needed
        dst = channel->dst.raw & (channel->control.unit_size ? ~3 : ~1); // TODO Investigate why the alignment is needed
        count = channel->count.raw;
        unit_size = channel->control.unit_size ? 4 : 2; // In  bytes

        switch (channel->control.dst_ctl) {
            case 0b00:      dst_step = unit_size; break;
            case 0b01:      dst_step = -unit_size; break;
            case 0b10:      dst_step = 0; break;
            case 0b11:      unimplemented(HS_DMA, "DMA transfers with increment+reload dest address isn't implemented."); break;
        }

        src_step = 0;
        switch (channel->control.src_ctl) {
            case 0b00:      src_step = unit_size; break;
            case 0b01:      src_step = -unit_size; break;
            case 0b10:      src_step = 0; break;
            case 0b11:      src_step = 0; break;
        }

        // A count of 0 is treated as max length.
        if (count == 0) {
            count = (i == 3 ? 0x10000 : 0x4000);
        }

        logln(
            HS_DMA,
            "DMA transfer from 0x%08x%c to 0x%08x%c (len=%#08x, unit_size=%u, channel %u)",
            src,
            src_step > 0 ? '+' : '-',
            dst,
            dst_step > 0 ? '+' : '-',
            count,
            unit_size,
            i
        );

        if (dst == 0x040000A0 || dst == 0x040000A4) {
            logln(HS_DMA, "FIFO transfer -- Ignored");
        } else {
            while (count > 0) {
                if (unit_size == 4) {
                    mem_write32(gba, dst, mem_read32(gba, src));
                } else { // unit_size == 2
                    mem_write16(gba, dst, mem_read16(gba, src));
                }
                src += src_step;
                dst += dst_step;
                --count;
            }
        }

        if (channel->control.irq_end) {
            unimplemented(HS_DMA, "IRQ at the end of DMA transfers isn't implemented yet.");
        }

        if (channel->control.repeat) {
            unimplemented(HS_DMA, "Repeat bit unimplemented");
        } else {
            channel->control.enable = false;
        }
    }
}