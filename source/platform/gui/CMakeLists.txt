cmake_minimum_required(VERSION 3.10)

project(hades_gui)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS "-fms-extensions -Wno-microsoft-anon-tag")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CIMGUI_DIR "${CMAKE_SOURCE_DIR}/external/cimgui/")
set(IMGUI_DIR "${CIMGUI_DIR}/imgui")
set(IGFD_DIR "${CMAKE_SOURCE_DIR}/external/imgui_file_dialog/")

if (WIN32)
    add_definitions("-DIMGUI_IMPL_API=extern \"C\" __declspec\(dllexport\)")
else(WIN32)
    add_definitions("-DIMGUI_IMPL_API=extern \"C\" ")
endif(WIN32)

add_definitions("-DHADES_VERSION=\"${HADES_VERSION}\"")

include_directories(
    "${CMAKE_SOURCE_DIR}/include/"
    "${CIMGUI_DIR}/"
    "${CIMGUI_DIR}/generator/output/"
    "${IMGUI_DIR}/"
    "${IGFD_DIR}/"
)

add_executable(hades_gui
    "main.c"
    "error.c"
    "game/game.c"
    "game/render.c"
    "game/screenshot.c"
    "menubar.c"
    "${CIMGUI_DIR}/cimgui.cpp"
    "${IMGUI_DIR}/imgui.cpp"
    "${IMGUI_DIR}/imgui_demo.cpp"
    "${IMGUI_DIR}/imgui_draw.cpp"
    "${IMGUI_DIR}/imgui_tables.cpp"
    "${IMGUI_DIR}/imgui_widgets.cpp"
    "${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp"
    "${IMGUI_DIR}/backends/imgui_impl_sdl.cpp"
    "${IGFD_DIR}/ImGuiFileDialog.cpp"
)

# OpenGL
set(OpenGL_GL_PREFERENCE GLVND)
find_package(OpenGL REQUIRED)

# sdl2
find_package(SDL2 REQUIRED)
include_directories(${SDL2_INCLUDE_DIR})

# sdl2_image
find_package(SDL2_image REQUIRED)
include_directories(${SDL2_IMAGE_INCLUDE_DIR})

# Glew
find_package(GLEW REQUIRED)
include_directories(${GLEW_INCLUDE_DIRS})

# pthread
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

target_link_libraries(
    hades_gui
    gba common Threads::Threads OpenGL::GL GLEW::GLEW ${SDL2_LIBRARY} ${SDL2_IMAGE_LIBRARY}
)

add_custom_command(
    TARGET hades_gui POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:hades_gui> ${CMAKE_BINARY_DIR}/hades$<TARGET_FILE_SUFFIX:hades_gui>
)

if(CI_WIN32_PACKAGING)
    add_custom_command(
        TARGET hades_gui POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_RUNTIME_DLLS:hades_gui> ${CMAKE_BINARY_DIR}/dll/
        COMMAND_EXPAND_LISTS
    )
endif(CI_WIN32_PACKAGING)