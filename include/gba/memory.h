/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#pragma once

#include <stdint.h>
#include "hades.h"

/*
** Access to the memory bus can either be sequential (the requested address follows the previous one)
** or non-sequential (the requested address is unrelated to the previous one)
*/
enum access_types {
    NON_SEQUENTIAL,
    SEQUENTIAL,
};

/*
** An enumeration of the different memory regions
** and other informations associated with them.
*/

#define BIOS_START              (0x00000000)
#define BIOS_END                (0x00003FFF)
#define BIOS_REGION             (BIOS_START >> 24)
#define BIOS_MASK               (BIOS_END - BIOS_START)
#define BIOS_SIZE               (BIOS_END - BIOS_START + 1)

#define EWRAM_START             (0x02000000)
#define EWRAM_END               (0x0203FFFF)
#define EWRAM_REGION            (EWRAM_START >> 24)
#define EWRAM_MASK              (EWRAM_END - EWRAM_START)
#define EWRAM_SIZE              (EWRAM_END - EWRAM_START + 1)

#define IWRAM_START             (0x03000000)
#define IWRAM_END               (0x03007FFF)
#define IWRAM_REGION            (IWRAM_START >> 24)
#define IWRAM_MASK              (IWRAM_END - IWRAM_START)
#define IWRAM_SIZE              (IWRAM_END - IWRAM_START + 1)

#define IO_START                (0x04000000)
#define IO_END                  (0x040003FF)
#define IO_REGION               (IO_START >> 24)
#define IO_MASK                 (IO_END - IO_START)
#define IO_SIZE                 (IO_END - IO_START + 1)

#define PALRAM_START            (0x05000000)
#define PALRAM_END              (0x050003FF)
#define PALRAM_REGION           (PALRAM_START >> 24)
#define PALRAM_MASK             (PALRAM_END - PALRAM_START)
#define PALRAM_SIZE             (PALRAM_END - PALRAM_START + 1)

#define VRAM_START              (0x06000000)
#define VRAM_END                (0x06017FFF)
#define VRAM_REGION             (VRAM_START >> 24)
#define VRAM_MASK_1             (0x00017FFF)
#define VRAM_MASK_2             (0x0001FFFF)
#define VRAM_SIZE               (VRAM_END - VRAM_START + 1)

#define OAM_START               (0x07000000)
#define OAM_END                 (0x070003FF)
#define OAM_REGION              (OAM_START >> 24)
#define OAM_MASK                (OAM_END - OAM_START)
#define OAM_SIZE                (OAM_END - OAM_START + 1)

#define CART_0_START            (0x08000000)
#define CART_0_END              (0x09FFFFFF)
#define CART_0_REGION_1         (CART_0_START >> 24)
#define CART_0_REGION_2         (CART_0_END >> 24)

#define CART_1_START            (0x0A000000)
#define CART_1_END              (0x0BFFFFFF)
#define CART_1_REGION_1         (CART_1_START >> 24)
#define CART_1_REGION_2         (CART_1_END >> 24)

#define CART_2_START            (0x0C000000)
#define CART_2_END              (0x0DFFFFFF)
#define CART_2_REGION_1         (CART_2_START >> 24)
#define CART_2_REGION_2         (CART_2_END >> 24)

#define CART_MASK               (CART_0_END - CART_0_START)
#define CART_SIZE               (CART_0_END - CART_0_START + 1)
#define CART_REGION_START       (CART_0_START >> 24)
#define CART_REGION_END         (CART_2_END >> 24)

#define SRAM_START              (0x0E000000)
#define SRAM_END                (0x0E00FFFF)
#define SRAM_SIZE               (SRAM_END - SRAM_START + 1)
#define SRAM_MASK               (SRAM_END - SRAM_START)
#define SRAM_REGION             (SRAM_START >> 24)

#define SRAM_MIRROR_START       (0x0F000000)
#define SRAM_MIRROR_END         (0x0F00FFFF)
#define SRAM_MIRROR_REGION      (SRAM_MIRROR_START >> 24)

#define FLASH_START             (0x0E000000)
#define FLASH_END               (0x0E00FFFF)
#define FLASH64_SIZE            (FLASH_END - FLASH_START + 1)
#define FLASH128_SIZE           (FLASH64_SIZE * 2)
#define FLASH_MASK              (FLASH_END - FLASH_START)

#define EEPROM_4K_SIZE          (0x200)
#define EEPROM_4K_ADDR_MASK     (0x1FF)
#define EEPROM_4K_ADDR_LEN      (6)
#define EEPROM_64K_SIZE         (0x2000)
#define EEPROM_64K_ADDR_MASK    (0x1FFF)
#define EEPROM_64K_ADDR_LEN     (14)

/*
** The different types of backup storage a game can use.
*/
enum backup_storage_types {
    BACKUP_MIN = -1,

    BACKUP_AUTO_DETECT = -1,

    BACKUP_NONE = 0,
    BACKUP_EEPROM_4K = 1,
    BACKUP_EEPROM_64K = 2,
    BACKUP_SRAM = 3,
    BACKUP_FLASH64 = 4,
    BACKUP_FLASH128 = 5,

    BACKUP_MAX = 5,
};

enum backup_storage_sources {
    BACKUP_SOURCE_AUTO_DETECT,
    BACKUP_SOURCE_MANUAL,
    BACKUP_SOURCE_DATABASE,
};

enum flash_states {
    FLASH_STATE_READY,
    FLASH_STATE_CMD_1,
    FLASH_STATE_CMD_2,
    FLASH_STATE_ERASE,
    FLASH_STATE_WRITE,
    FLASH_STATE_BANK,
};

enum flash_cmds {
    FLASH_CMD_ENTER_IDENTITY    = 0x90,
    FLASH_CMD_EXIT_IDENTITY     = 0xF0,
    FLASH_CMD_PREP_ERASE        = 0x80,
    FLASH_CMD_ERASE_CHIP        = 0x10,
    FLASH_CMD_ERASE_SECTOR      = 0x30,
    FLASH_CMD_WRITE             = 0xA0,
    FLASH_CMD_SET_BANK          = 0xB0,
};

struct flash {
    enum flash_states state;
    bool identity_mode;
    bool bank;
};

enum eeprom_states {
    EEPROM_STATE_READY,
    EEPROM_STATE_CMD,
    EEPROM_STATE_TRANSFER_ADDR,
    EEPROM_STATE_TRANSFER_DATA,
    EEPROM_STATE_TRANSFER_JUNK,
    EEPROM_STATE_END,
};

enum eeprom_cmds {
    EEPROM_CMD_READ,
    EEPROM_CMD_WRITE,
};

struct eeprom {
    uint32_t mask;
    uint32_t range;

    enum eeprom_states state;
    enum eeprom_cmds cmd;

    uint32_t address_mask;
    uint32_t address_len;

    uint32_t transfer_address;
    uint64_t transfer_data;
    uint32_t transfer_len;
};

struct prefetch_buffer {
    uint32_t head;
    uint32_t tail;
    uint32_t countdown;
    uint32_t size;
    uint32_t capacity;
    uint32_t insn_len;
    uint32_t reload;
    bool enabled;
};

/*
** The overall memory of the Gameboy Advance.
*/
struct memory {
    // General Internal Memory
    uint8_t bios[BIOS_SIZE];
    uint8_t ewram[EWRAM_SIZE];
    uint8_t iwram[IWRAM_SIZE];

    // Internal Display Memory
    uint8_t palram[PALRAM_SIZE];
    uint8_t vram[VRAM_SIZE];
    uint8_t oam[OAM_SIZE];

    // External Memory (Game Pak)
    uint8_t rom[CART_SIZE];
    size_t rom_size;

    // Backup Storage
    uint8_t *backup_storage_data;
    enum backup_storage_types backup_storage_type;
    enum backup_storage_sources backup_storage_source;
    atomic_bool backup_storage_dirty;

    // Flash memory
    struct flash flash;

    // EEPROM memory
    struct eeprom eeprom;

    // Prefetch
    struct prefetch_buffer pbuffer;

    // Open Bus
    uint32_t bios_bus;

    // Set when the cartridge memory bus is in used
    bool gamepak_bus_in_use;
};

/*
** The different timings at which a DMA transfer can occur.
*/
enum dma_timings {
    DMA_TIMING_NOW              = 0,
    DMA_TIMING_VBLANK           = 1,
    DMA_TIMING_HBLANK           = 2,
    DMA_TIMING_SPECIAL          = 3,
};

struct core;
struct gba;
struct dma_channel;

/* gba/memory/dma.c */
void mem_io_dma_ctl_write8(struct gba *gba, struct dma_channel *, uint8_t val);
bool mem_dma_is_fifo(struct gba const *gba, uint32_t dma_channel_idx, uint32_t fifo_idx);
void mem_schedule_dma_transfers_for(struct gba *gba, uint32_t channel_idx, enum dma_timings timing);
void mem_schedule_dma_transfers(struct gba *gba, enum dma_timings timing);
void mem_dma_do_all_pending_transfers(struct gba *gba);

/* gba/memory/io.c */
uint8_t mem_io_read8(struct gba const *gba, uint32_t addr);
void mem_io_write8(struct gba *gba, uint32_t addr, uint8_t val);

/* gba/memory/memory.c */
void mem_reset(struct memory *memory);
void mem_access(struct gba *gba, uint32_t addr, uint32_t size, enum access_types access_type);
void mem_update_waitstates(struct gba const *gba);
void mem_prefetch_buffer_access(struct gba *gba, uint32_t addr, uint32_t intended_cycles);
void mem_prefetch_buffer_step(struct gba *gba, uint32_t cycles);
uint32_t mem_openbus_read(struct gba const *gba, uint32_t addr);
uint8_t mem_read8(struct gba *gba, uint32_t addr, enum access_types access_type);
uint8_t mem_read8_raw(struct gba *gba, uint32_t addr);
uint16_t mem_read16(struct gba *gba, uint32_t addr, enum access_types access_type);
uint16_t mem_read16_raw(struct gba *gba, uint32_t addr);
uint32_t mem_read16_ror(struct gba *gba, uint32_t addr, enum access_types access_type);
uint32_t mem_read32(struct gba *gba, uint32_t addr, enum access_types access_type);
uint32_t mem_read32_raw(struct gba *gba, uint32_t addr);
uint32_t mem_read32_ror(struct gba *gba, uint32_t addr, enum access_types access_type);
void mem_write8(struct gba *gba, uint32_t addr, uint8_t val, enum access_types access_type);
void mem_write8_raw(struct gba *gba, uint32_t addr, uint8_t val);
void mem_write16(struct gba *gba, uint32_t addr, uint16_t val, enum access_types access_type);
void mem_write16_raw(struct gba *gba, uint32_t addr, uint16_t val);
void mem_write32(struct gba *gba, uint32_t addr, uint32_t val, enum access_types access_type);
void mem_write32_raw(struct gba *gba, uint32_t addr, uint32_t val);

/* gba/memory/storage/eeprom.c */
uint8_t mem_eeprom_read8(struct gba *gba);
void mem_eeprom_write8(struct gba *gba, bool val);

/* gba/memory/storage/flash.c */
uint8_t mem_flash_read8(struct gba const *gba, uint32_t addr);
void mem_flash_write8(struct gba *gba, uint32_t addr, uint8_t val);

/* gba/memory/storage/storage.c */
extern size_t backup_storage_sizes[];
void mem_backup_storage_detect(struct gba *gba);
void mem_backup_storage_init(struct gba *gba);
uint8_t mem_backup_storage_read8(struct gba const *gba, uint32_t addr);
void mem_backup_storage_write8(struct gba *gba, uint32_t addr, uint8_t value);
void mem_backup_storage_write_to_disk(struct gba *gba);

/* gba/quicksave.c */
void quicksave(struct gba const *gba, char const *);
void quickload(struct gba *gba, char const *);

/*
** The following memory-accessors are used by the PPU for fast memory access
** with no overhead and to prevent the cycle counter to be incremented.
*/

#define mem_palram_read8(gba, addr)         ((gba)->memory.palram[(addr) & PALRAM_MASK])
#define mem_vram_read8(gba, addr)           ((gba)->memory.vram[(addr) & (((addr) & 0x10000) ? VRAM_MASK_1 : VRAM_MASK_2)])
#define mem_oam_read8(gba, addr)            ((gba)->memory.oam[(addr) & OAM_MASK])
#define mem_palram_read16(gba, addr)        (*(uint16_t *)((uint8_t *)(gba)->memory.palram + ((addr) & PALRAM_MASK)))
#define mem_vram_read16(gba, addr)          (*(uint16_t *)((uint8_t *)(gba)->memory.vram + ((addr) & (((addr) & 0x10000) ? VRAM_MASK_1 : VRAM_MASK_2))))
#define mem_oam_read16(gba, addr)           (*(uint16_t *)((uint8_t *)(gba)->memory.oam + ((addr) & OAM_MASK)))
