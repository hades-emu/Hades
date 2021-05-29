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
    struct gba *gba
) {
    size_t i;

    i = 0;
    while (i < 4) {
        struct dma_channel *channel;
        uint32_t src;
        int32_t src_step;
        uint32_t dst;
        int32_t dst_step;
        uint32_t count;

        channel = gba->memory.dma_channels + i;

        // Skip channels that aren't enabled
        if (!channel->control.enable) {
            ++i;
            continue;
        }

        src = channel->src.raw;
        dst = channel->dst.raw;
        count = channel->count.raw;

        // A count of 0 is treated as max length.
        if (count == 0) {
            count = (i == 3 ? 0x10000 : 0x4000);
        }

        if (dst == 0x040000A0 || dst == 0x040000A4) {
            hs_logln(HS_IO, "FIFO DMA transfer from 0x%08x to 0x%08x (len=%#08x, channel %u)\n", src, dst, count, i);
        } else {
            panic(HS_IO, "DMA transfer from 0x%08x to 0x%08x (len=%#08x, channel %u)\n", src, dst, count, i);
        }

        channel->control.enable = false;

        ++i;
    }
}