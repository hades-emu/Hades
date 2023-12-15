from typing import List
from check import Test

TESTS_SUITE: List[Test] = [

    # Jsmolka's arm.gba & thumg.gba
    # https://github.com/jsmolka/gba-tests
    Test(
        name="Jsmolka - Arm.gba",
        rom='arm.gba',
        code='''
            frame 10
            screenshot ./.tests_screenshots/arm.png
        ''',
        screenshot='arm.png',
    ),
    Test(
        name="Jsmolka - Thumb.gba",
        rom='thumb.gba',
        code='''
            frame 10
            screenshot ./.tests_screenshots/thumb.png
        ''',
        screenshot='thumb.png',
    ),

    # Hades Tests
    # https://github.com/Arignir/Hades-Tests
    Test(
        name="Hades Tests - DMA Start Delay",
        rom='dma-start-delay.gba',
        code='''
            frame 20
            screenshot ./.tests_screenshots/dma_start_delay.png
        ''',
        screenshot='dma_start_delay.png',
        skip=True,
    ),
    Test(
        name="Hades Tests - Openbus BIOS",
        rom='openbus-bios.gba',
        code='''
            frame 20
            screenshot ./.tests_screenshots/openbus_bios.png
        ''',
        screenshot='openbus_bios.png',
    ),
    Test(
        name="Hades Tests - Timer Basic",
        rom='timer-basic.gba',
        code='''
            frame 20
            screenshot ./.tests_screenshots/timer_basic.png
        ''',
        screenshot='timer_basic.png',
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
