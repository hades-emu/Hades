from typing import List
from check import Test

TESTS_SUITE: List[Test] = [

    # Jsmolka's test roms
    # https://github.com/jsmolka/gba-tests
    Test(
        name="Jsmolka - arm.gba",
        rom='jsmolka-arm.gba',
        code='''
            frame 10
            screenshot ./.tests_screenshots/jsmolka_arm.png
        ''',
        screenshot='jsmolka_arm.png',
    ),
    Test(
        name="Jsmolka - bios.gba",
        rom='jsmolka-bios.gba',
        code='''
            frame 10
            screenshot ./.tests_screenshots/jsmolka_bios.png
        ''',
        screenshot='jsmolka_bios.png',
        skip=True,
    ),
    Test(
        name="Jsmolka - memory.gba",
        rom='jsmolka-memory.gba',
        code='''
            frame 10
            screenshot ./.tests_screenshots/jsmolka_memory.png
        ''',
        screenshot='jsmolka_memory.png',
    ),
    Test(
        name="Jsmolka - nes.gba",
        rom='jsmolka-nes.gba',
        code='''
            frame 10
            screenshot ./.tests_screenshots/jsmolka_nes.png
        ''',
        screenshot='jsmolka_nes.png',
    ),
    Test(
        name="Jsmolka - thumb.gba",
        rom='jsmolka-thumb.gba',
        code='''
            frame 10
            screenshot ./.tests_screenshots/jsmolka_thumb.png
        ''',
        screenshot='jsmolka_thumb.png',
    ),
    Test(
        name="Jsmolka - unsafe.gba",
        rom='jsmolka-unsafe.gba',
        code='''
            frame 10
            screenshot ./.tests_screenshots/jsmolka_unsafe.png
        ''',
        screenshot='jsmolka_unsafe.png',
    ),
    Test(
        name="Jsmolka - save/sram.gba",
        rom='jsmolka-sram.gba',
        code='''
            frame 10
            screenshot ./.tests_screenshots/jsmolka_sram.png
        ''',
        screenshot='jsmolka_sram.png',
        skip=True,
    ),
    Test(
        name="Jsmolka - save/none.gba",
        rom='jsmolka-none.gba',
        code='''
            frame 10
            screenshot ./.tests_screenshots/jsmolka_none.png
        ''',
        screenshot='jsmolka_none.png',
    ),
    Test(
        name="Jsmolka - save/flash64.gba",
        rom='jsmolka-flash64.gba',
        code='''
            frame 10
            screenshot ./.tests_screenshots/jsmolka_flash64.png
        ''',
        screenshot='jsmolka_flash64.png',
        skip=True,
    ),
    Test(
        name="Jsmolka - save/flash128.gba",
        rom='jsmolka-flash128.gba',
        code='''
            frame 10
            screenshot ./.tests_screenshots/jsmolka_flash128.png
        ''',
        screenshot='jsmolka_flash128.png',
        skip=True,
    ),

    # mGBA suite
    # https://github.com/mgba-emu/suite
    Test(
        name="mGBA Suite - Memory",
        rom='mgba-suite.gba',
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
        rom='mgba-suite.gba',
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
        rom='mgba-suite.gba',
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
        rom='mgba-suite.gba',
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
        rom='mgba-suite.gba',
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
        rom='mgba-suite.gba',
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
        rom='mgba-suite.gba',
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
        rom='mgba-suite.gba',
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
        rom='mgba-suite.gba',
        code='''
            key down true
            frame 90
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
        rom='mgba-suite.gba',
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

    # Hades Tests
    # https://github.com/Arignir/Hades-Tests
    Test(
        name="Hades Tests - DMA Start Delay",
        rom='hades-dma-start-delay.gba',
        code='''
            frame 20
            screenshot ./.tests_screenshots/hades_dma_start_delay.png
        ''',
        screenshot='hades_dma_start_delay.png',
        skip=True,
    ),
    Test(
        name="Hades Tests - Openbus BIOS",
        rom='hades-openbus-bios.gba',
        code='''
            frame 20
            screenshot ./.tests_screenshots/hades_openbus_bios.png
        ''',
        screenshot='hades_openbus_bios.png',
    ),
    Test(
        name="Hades Tests - Timer Basic",
        rom='hades-timer-basic.gba',
        code='''
            frame 20
            screenshot ./.tests_screenshots/hades_timer_basic.png
        ''',
        screenshot='hades_timer_basic.png',
    ),

    # AGS
    Test(
        name="AGS - Aging Tests",
        rom='ags.gba',
        code='''
            frame 425
            screenshot ./.tests_screenshots/ags_01.png
        ''',
        screenshot='ags_01.png',
    )
]
