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
    struct dma_channel *channel
) {
    channel->is_fifo = (channel->index >= 1 && channel->index <= 2 && channel->control.timing == DMA_TIMING_SPECIAL);
    channel->is_video = (channel->index == 3 && channel->control.timing == DMA_TIMING_SPECIAL);
    if (channel->is_fifo) {
        channel->internal_count = 4;
    } else {
        channel->internal_count = channel->count.raw;
        channel->internal_count &= count_mask[channel->index];
    }
    channel->internal_src = channel->src.raw & (channel->control.unit_size ? ~3 : ~1);
    channel->internal_src &= src_mask[channel->index];
    channel->internal_dst = channel->dst.raw & (channel->control.unit_size ? ~3 : ~1);
    channel->internal_dst &= dst_mask[channel->index];
}

/*
** Run a single DMA transfer.
*/
static
void
dma_run_channel(
    struct gba *gba,
    struct dma_channel *channel,
    bool first
) {
    struct dma_channel *prev_dma;
    enum access_type access;
    int32_t src_step;
    int32_t dst_step;
    int32_t unit_size;

    prev_dma = gba->core.current_dma;
    gba->core.current_dma = channel;

    // The first DMA take at least two internal cycles
    // (Supposedly to transition from CPU to DMA)
    if (first) {
        core_idle_for(gba, 2);
    }

    bool src_in_gamepak = ((channel->internal_src >> 24) >= CART_REGION_START && (channel->internal_src) <= CART_REGION_END);
    bool dst_in_gamepak = ((channel->internal_dst >> 24) >= CART_REGION_START && (channel->internal_dst) <= CART_REGION_END);

    if ((src_in_gamepak || dst_in_gamepak)) {
        core_idle_for(gba, 2);
    }

    unit_size = channel->control.unit_size ? sizeof(uint32_t) : sizeof(uint16_t); // In  bytes

    if (channel->is_fifo) {
        dst_step = 0;
    } else {

        switch (channel->control.dst_ctl) {
            case 0b00:      dst_step = unit_size; break;
            case 0b01:      dst_step = -unit_size; break;
            case 0b10:      dst_step = 0; break;
            case 0b11:      dst_step = unit_size; break;
        }
    }

    switch (channel->control.src_ctl) {
        case 0b00:      src_step = unit_size; break;
        case 0b01:      src_step = -unit_size; break;
        case 0b10:      src_step = 0; break;
        case 0b11:      src_step = 0; break;
    }

    // A count of 0 is treated as max length.
    if (channel->internal_count == 0) {
        channel->internal_count = count_mask[channel->index] + 1;
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
        channel->index
    );

    access = NON_SEQUENTIAL;
    while (channel->internal_count > 0) {
        if (unit_size == 4) {
            if (channel->internal_src >= EWRAM_START) {
                channel->bus = mem_read32(gba, channel->internal_src, access);
            } else {
                core_idle(gba);
            }
            mem_write32(gba, channel->internal_dst, channel->bus, access);
        } else { // unit_size == 2
            if (channel->internal_src >= EWRAM_START) {

                /*
                ** Not sure what's the expected behaviour, this is more
                ** or less random.
                */
                channel->bus <<= 16;
                channel->bus |= mem_read16(gba, channel->internal_src, access);
            } else {
                core_idle(gba);
            }
            mem_write16(gba, channel->internal_dst, channel->bus, access);
        }
        channel->internal_src += src_step;
        channel->internal_dst += dst_step;
        channel->internal_count -= 1;
        access = SEQUENTIAL;
    }

    if (channel->control.irq_end) {
        core_trigger_irq(gba, IRQ_DMA0 + channel->index);
    }

    if (channel->control.repeat) {
        if (channel->is_fifo) {
            channel->internal_count = 4;
        } else if (channel->is_video) {
            if (gba->io.vcount.raw < GBA_SCREEN_HEIGHT + 1) {
                channel->internal_count = channel->count.raw;
                channel->internal_count &= count_mask[channel->index];

                if (channel->control.dst_ctl == 0b11) {
                    channel->internal_dst = channel->dst.raw & (channel->control.unit_size ? ~3 : ~1);
                    channel->internal_dst &= dst_mask[channel->index];
                }
            } else {
                channel->control.enable = false;
            }
        } else {
            channel->internal_count = channel->count.raw;
            channel->internal_count &= count_mask[channel->index];

            if (channel->control.dst_ctl == 0b11) {
                channel->internal_dst = channel->dst.raw & (channel->control.unit_size ? ~3 : ~1);
                channel->internal_dst &= dst_mask[channel->index];
            }
        }
    } else {
        channel->control.enable = false;
    }

    gba->core.current_dma = prev_dma;
}

/*
** Go through all DMA channels and process all the ones waiting for the given timing.
*/
static
void
mem_dma_do_all_transfers(
    struct gba *gba,
    union event_data data
) {
    enum dma_timings timing;
    bool first;
    size_t i;

    first = !gba->core.current_dma;
    timing = data.u32;

    for (i = 0; i < 4; ++i) {
        struct dma_channel *channel;

        channel = &gba->io.dma[i];

        // Skip channels that aren't enabled or that shouldn't happen at the given timing
        if (!channel->control.enable || channel->control.timing != timing) {
            continue;
        }

        dma_run_channel(gba, channel, first);
        first = false;
    }
}

static
void
mem_dma_run_fifo(
    struct gba *gba,
    union event_data data
) {
    struct dma_channel *channel;

    channel = &gba->io.dma[data.u32];
    if (channel->control.enable && channel->control.timing == DMA_TIMING_SPECIAL) {
        dma_run_channel(gba, channel, !(gba->core.current_dma));
    }
}

static
void
mem_dma_run_video(
    struct gba *gba,
    union event_data data __unused
) {
    struct dma_channel *channel;

    channel = &gba->io.dma[3];
    if (channel->control.enable && channel->control.timing == DMA_TIMING_SPECIAL) {
        dma_run_channel(gba, channel, !(gba->core.current_dma));
    }
}

void
mem_schedule_dma_transfers(
    struct gba *gba,
    enum dma_timings timing
) {
    sched_add_event(
        gba,
        NEW_FIX_EVENT_DATA(
            gba->core.cycles + 2,
            mem_dma_do_all_transfers,
            (union event_data){ .u32 = timing }
        )
    );
}

void
mem_schedule_dma_fifo(
    struct gba *gba,
    uint32_t dma_channel_idx
) {
    sched_add_event(
        gba,
        NEW_FIX_EVENT_DATA(
            gba->core.cycles + 2,
            mem_dma_run_fifo,
            (union event_data){ .u32 = dma_channel_idx }
        )
    );
}

void
mem_schedule_dma_video(
    struct gba *gba
) {
    sched_add_event(
        gba,
        NEW_FIX_EVENT(
            gba->core.cycles + 2,
            mem_dma_run_video
        )
    );
}

bool
mem_dma_is_fifo(
    struct gba const *gba,
    uint32_t dma_channel_idx,
    uint32_t fifo_idx
) {
    struct dma_channel const *dma;

    dma = &gba->io.dma[dma_channel_idx];
    return (
           dma->control.enable
        && dma->control.timing == DMA_TIMING_SPECIAL
        && dma->dst.raw == (fifo_idx == FIFO_A ? IO_REG_FIFO_A : IO_REG_FIFO_B)
    );
}