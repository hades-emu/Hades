/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#pragma once

#include "hades.h"

struct app;

/* gui/sdl/audio.c */
void gui_sdl_audio_init(struct app *app);
void gui_sdl_audio_cleanup(struct app *app);

/* gui/sdl/init.c */
void gui_sdl_init(struct app *app);
void gui_sdl_cleanup(struct app *app);

/* gui/sdl/input.c */
void gui_sdl_setup_default_binds(struct app *app);
void gui_sdl_handle_inputs(struct app *app);

/* gui/sdl/video.c */
void gui_sdl_video_init(struct app *app);
void gui_sdl_video_cleanup(struct app *app);
void gui_sdl_video_render_frame(struct app *app);

/* gui/windows/keybinds.c */
void gui_win_keybinds_editor(struct app *app);

/* gui/windows/error.c */
void gui_new_error(struct app *app, char *msg);
void gui_win_error(struct app *app);

/* gui/windows.c */
void gui_win_game(struct app *app);

/* gui/windows/menubar.c */
void gui_win_menubar(struct app *app);

/* config.c */
void gui_config_load(struct app *app);
void gui_config_save(struct app *app);
void gui_config_push_recent_rom(struct app *app);
