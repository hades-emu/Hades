/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#ifndef PLATFORM_GUI_COMMON_H
# define PLATFORM_GUI_COMMON_H

struct app;

/* platform/gui/common/game.c */
void gui_game_reset(struct app *app);
void gui_game_stop(struct app *app);
void gui_game_run(struct app *app);
void gui_game_pause(struct app *app);
void gui_game_write_backup(struct app *app);

#endif /* !PLATFORM_GUI_COMMON_H */