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

        panic(HS_IO, "DMA transfer from %#08x to %#08x (len=%#08x)\n", src, dst, count);

        channel->control.enable = false;

        ++i;
    }
}