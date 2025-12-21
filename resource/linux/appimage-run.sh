#!/usr/bin/env bash

# Prefer Wayland only if libdecor exists on host
if [ "$XDG_SESSION_TYPE" == "wayland" ] && ldconfig -p 2> /dev/null | grep -q libdecor-0; then
    export SDL_VIDEODRIVER=wayland
else
    export SDL_VIDEODRIVER=x11
fi

exec "$APPDIR/usr/bin/hades"
