from enum import Enum
from typing import List

from rom import Rom
from test import Test


class TestRoms(Enum):
    JSMOLKA_ARM = Rom('jsmolka-arm', 'https://raw.githubusercontent.com/jsmolka/gba-tests/master/arm/arm.gba')
    JSMOLKA_BIOS = Rom('jsmolka-bios', 'https://raw.githubusercontent.com/jsmolka/gba-tests/master/bios/bios.gba')
    JSMOLKA_MEMORY = Rom('jsmolka-memory', 'https://raw.githubusercontent.com/jsmolka/gba-tests/master/memory/memory.gba')
    JSMOLKA_NES = Rom('jsmolka-nes', 'https://raw.githubusercontent.com/jsmolka/gba-tests/master/nes/nes.gba')
    JSMOLKA_THUMB = Rom('jsmolka-thumb', 'https://raw.githubusercontent.com/jsmolka/gba-tests/master/thumb/thumb.gba')
    JSMOLKA_UNSAFE = Rom('jsmolka-unsafe', 'https://raw.githubusercontent.com/jsmolka/gba-tests/master/unsafe/unsafe.gba')
    JSMOLKA_SAVE_FLASH64 = Rom('jsmolka-save-flash64', 'https://raw.githubusercontent.com/jsmolka/gba-tests/master/save/flash64.gba')
    JSMOLKA_SAVE_FLASH128 = Rom('jsmolka-save-flash128', 'https://raw.githubusercontent.com/jsmolka/gba-tests/master/save/flash128.gba')
    JSMOLKA_SAVE_NONE = Rom('jsmolka-save-none', 'https://raw.githubusercontent.com/jsmolka/gba-tests/master/save/none.gba')
    JSMOLKA_SAVE_SRAM = Rom('jsmolka-save-sram', 'https://raw.githubusercontent.com/jsmolka/gba-tests/master/save/sram.gba')

    MGBA_SUITE = Rom('mgba-suite', 'https://s3.amazonaws.com/mgba/suite-latest.zip')

    HADES_DMA_START_DELAY = Rom('hades-dma-start-delay', 'https://raw.githubusercontent.com/Arignir/Hades-Tests/master/roms/dma-start-delay.gba')
    HADES_DMA_LATCH = Rom('hades-dma-latch', 'https://raw.githubusercontent.com/Arignir/Hades-Tests/master/roms/dma-latch.gba')
    HADES_BIOS_OPENBUS = Rom('hades-bios-openbus', 'https://raw.githubusercontent.com/Arignir/Hades-Tests/master/roms/bios-openbus.gba')
    HADES_TIMER_BASIC = Rom('hades-timer-basic', 'https://raw.githubusercontent.com/Arignir/Hades-Tests/master/roms/timer-basic.gba')

    NBA_DMA_START_DELAY = Rom('nba-dma-start-delay', 'https://raw.githubusercontent.com/nba-emu/hw-test/master/dma/start-delay/start-delay.gba')
    NBA_DMA_LATCH = Rom('nba-dma-latch', 'https://raw.githubusercontent.com/nba-emu/hw-test/master/dma/latch/latch.gba')
    NBA_TIMER_RELOAD = Rom('nba-timer-reload', 'https://raw.githubusercontent.com/nba-emu/hw-test/master/timer/reload/reload.gba')
    NBA_TIMER_START_STOP = Rom('nba-timer-start-stop', 'https://raw.githubusercontent.com/nba-emu/hw-test/master/timer/start-stop/start-stop.gba')
    NBA_IRQ_DELAY = Rom('nba-irq-delay', 'https://raw.githubusercontent.com/nba-emu/hw-test/master/irq/irq-delay/irq-delay.gba')

    AGS = Rom('ags', None)


TESTS_SUITE: List[Test] = [

    # Jsmolka's test roms
    # https://github.com/jsmolka/gba-tests
    Test(
        name="Jsmolka - arm.gba",
        rom=TestRoms.JSMOLKA_ARM.value,
        code='''
            frame 10
            screenshot ./.tests_screenshots/jsmolka_arm.png
        ''',
        screenshot='jsmolka_arm.png',
    ),
    Test(
        name="Jsmolka - bios.gba",
        rom=TestRoms.JSMOLKA_BIOS.value,
        code='''
            frame 10
            screenshot ./.tests_screenshots/jsmolka_bios.png
        ''',
        screenshot='jsmolka_bios.png',
    ),
    Test(
        name="Jsmolka - memory.gba",
        rom=TestRoms.JSMOLKA_MEMORY.value,
        code='''
            frame 10
            screenshot ./.tests_screenshots/jsmolka_memory.png
        ''',
        screenshot='jsmolka_memory.png',
    ),
    Test(
        name="Jsmolka - nes.gba",
        rom=TestRoms.JSMOLKA_NES.value,
        code='''
            frame 10
            screenshot ./.tests_screenshots/jsmolka_nes.png
        ''',
        screenshot='jsmolka_nes.png',
    ),
    Test(
        name="Jsmolka - thumb.gba",
        rom=TestRoms.JSMOLKA_THUMB.value,
        code='''
            frame 10
            screenshot ./.tests_screenshots/jsmolka_thumb.png
        ''',
        screenshot='jsmolka_thumb.png',
    ),
    Test(
        name="Jsmolka - unsafe.gba",
        rom=TestRoms.JSMOLKA_UNSAFE.value,
        code='''
            frame 10
            screenshot ./.tests_screenshots/jsmolka_unsafe.png
        ''',
        screenshot='jsmolka_unsafe.png',
    ),
    Test(
        name="Jsmolka - save/sram.gba",
        rom=TestRoms.JSMOLKA_SAVE_SRAM.value,
        code='''
            frame 10
            screenshot ./.tests_screenshots/jsmolka_sram.png
        ''',
        screenshot='jsmolka_sram.png',
    ),
    Test(
        name="Jsmolka - save/none.gba",
        rom=TestRoms.JSMOLKA_SAVE_NONE.value,
        code='''
            frame 10
            screenshot ./.tests_screenshots/jsmolka_none.png
        ''',
        screenshot='jsmolka_none.png',
    ),
    Test(
        name="Jsmolka - save/flash64.gba",
        rom=TestRoms.JSMOLKA_SAVE_FLASH64.value,
        code='''
            frame 110
            screenshot ./.tests_screenshots/jsmolka_flash64.png
        ''',
        screenshot='jsmolka_flash64.png',
    ),
    Test(
        name="Jsmolka - save/flash128.gba",
        rom=TestRoms.JSMOLKA_SAVE_FLASH128.value,
        code='''
            frame 110
            screenshot ./.tests_screenshots/jsmolka_flash128.png
        ''',
        screenshot='jsmolka_flash128.png',
    ),

    # mGBA suite
    # https://github.com/mgba-emu/suite
    Test(
        name="mGBA Suite - Memory",
        rom=TestRoms.MGBA_SUITE.value,
        code='''
            key a true
            frame 20
            key a false
            frame 100

            screenshot ./.tests_screenshots/mgba_suite_memory.png
        ''',
        screenshot='mgba_suite_memory.png',
    ),
    Test(
        name="mGBA Suite - IO",
        rom=TestRoms.MGBA_SUITE.value,
        code='''
            key down true
            frame 20
            key down false
            key a true
            frame 20
            key a false
            frame 100

            screenshot ./.tests_screenshots/mgba_suite_io.png
        ''',
        screenshot='mgba_suite_io.png',
    ),
    Test(
        name="mGBA Suite - Timing",  # NOTE: Only passing 1918/2020 tests for now.
        rom=TestRoms.MGBA_SUITE.value,
        code='''
            key down true
            frame 40
            key down false
            key a true
            frame 20
            key a false
            frame 200

            screenshot ./.tests_screenshots/mgba_suite_timing.png
        ''',
        screenshot='mgba_suite_timing.png',
    ),
    Test(
        name="mGBA Suite - Timer Count-Up",  # NOTE: Only passing 211/936 tests for now.
        rom=TestRoms.MGBA_SUITE.value,
        code='''
            key down true
            frame 50
            key down false
            key a true
            frame 20
            key a false
            frame 150

            screenshot ./.tests_screenshots/mgba_suite_timer_count_up.png
        ''',
        screenshot='mgba_suite_timer_count_up.png',
    ),
    Test(
        name="mGBA Suite - Timer IRQ",  # NOTE: Only passing 28/90 tests for now.
        rom=TestRoms.MGBA_SUITE.value,
        code='''
            key down true
            frame 60
            key down false
            key a true
            frame 20
            key a false

            screenshot ./.tests_screenshots/mgba_suite_timer_irq.png
        ''',
        screenshot='mgba_suite_timer_irq.png',
    ),
    Test(
        name="mGBA Suite - Shifter",
        rom=TestRoms.MGBA_SUITE.value,
        code='''
            key down true
            frame 70
            key down false
            key a true
            frame 20
            key a false

            screenshot ./.tests_screenshots/mgba_suite_shifter.png
        ''',
        screenshot='mgba_suite_shifter.png',
    ),
    Test(
        name="mGBA Suite - Carry",
        rom=TestRoms.MGBA_SUITE.value,
        code='''
            key down true
            frame 80
            key down false
            key a true
            frame 20
            key a false

            screenshot ./.tests_screenshots/mgba_suite_carry.png
        ''',
        screenshot='mgba_suite_carry.png',
    ),
    Test(
        name="mGBA Suite - Multiply Long",  # NOTE: Only passing 52/72 tests for now.
        rom=TestRoms.MGBA_SUITE.value,
        code='''
            key down true
            frame 85
            key down false
            key a true
            frame 20
            key a false

            screenshot ./.tests_screenshots/mgba_suite_multiply_long.png
        ''',
        screenshot='mgba_suite_multiply_long.png',
    ),
    Test(
        name="mGBA Suite - BIOS",
        rom=TestRoms.MGBA_SUITE.value,
        code='''
            key down true
            frame 95
            key down false
            key a true
            frame 20
            key a false

            screenshot ./.tests_screenshots/mgba_suite_bios.png
        ''',
        screenshot='mgba_suite_bios.png',
    ),
    Test(
        name="mGBA Suite - DMA",  # NOTE: Only passing 1156/1256 tests for now.
        rom=TestRoms.MGBA_SUITE.value,
        code='''
            key down true
            frame 100
            key down false
            key a true
            frame 20
            key a false
            frame 130

            screenshot ./.tests_screenshots/mgba_suite_dma.png
        ''',
        screenshot='mgba_suite_dma.png',
    ),

    # NBA Hardware Tests
    # https://github.com/nba-emu/hw-test
    Test(
        name="NBA HW-Tests - Timer Reload",
        rom=TestRoms.NBA_TIMER_RELOAD.value,
        code='''
            frame 15

            screenshot ./.tests_screenshots/nba_timer_reload.png
        ''',
        screenshot='nba_timer_reload.png',
    ),
    Test(
        name="NBA HW-Tests - Timer Start/Stop",
        rom=TestRoms.NBA_TIMER_START_STOP.value,
        code='''
            frame 15

            screenshot ./.tests_screenshots/nba_timer_start_stop.png
        ''',
        screenshot='nba_timer_start_stop.png',
    ),
    Test(
        name="NBA HW-Tests - DMA Latch",
        rom=TestRoms.NBA_DMA_LATCH.value,
        code='''
            frame 15

            screenshot ./.tests_screenshots/nba_dma_latch.png
        ''',
        screenshot='nba_dma_latch.png',
    ),
    Test(
        name="NBA HW-Tests - DMA Start Delay",
        rom=TestRoms.NBA_DMA_START_DELAY.value,
        code='''
            frame 15

            screenshot ./.tests_screenshots/nba_dma_start_delay.png
        ''',
        screenshot='nba_dma_start_delay.png',
    ),
    Test(
        name="NBA HW-Tests - IRQ Delay",
        rom=TestRoms.NBA_IRQ_DELAY.value,
        code='''
            frame 15

            screenshot ./.tests_screenshots/nba_irq_delay.png
        ''',
        screenshot='nba_irq_delay.png',
    ),

    # Hades Tests
    # https://github.com/hades-emu/Hades-Tests
    Test(
        name="Hades Tests - DMA Latch",
        rom=TestRoms.HADES_DMA_LATCH.value,
        code='''
            frame 20
            screenshot ./.tests_screenshots/hades_dma_latch.png
        ''',
        screenshot='hades_dma_latch.png',
    ),
    Test(
        name="Hades Tests - DMA Start Delay",
        rom=TestRoms.HADES_DMA_START_DELAY.value,
        code='''
            frame 20
            screenshot ./.tests_screenshots/hades_dma_start_delay.png
        ''',
        screenshot='hades_dma_start_delay.png',
        skip=True,
    ),
    Test(
        name="Hades Tests - BIOS Openbus",
        rom=TestRoms.HADES_BIOS_OPENBUS.value,
        code='''
            frame 20
            screenshot ./.tests_screenshots/hades_bios_openbus.png
        ''',
        screenshot='hades_bios_openbus.png',
    ),
    Test(
        name="Hades Tests - Timer Basic",
        rom=TestRoms.HADES_TIMER_BASIC.value,
        code='''
            frame 20
            screenshot ./.tests_screenshots/hades_timer_basic.png
        ''',
        screenshot='hades_timer_basic.png',
    ),

    # AGS
    Test(
        name="AGS - Aging Tests",
        rom=TestRoms.AGS.value,
        code='''
            frame 425
            screenshot ./.tests_screenshots/ags_01.png
        ''',
        screenshot='ags_01.png',
    )
]
