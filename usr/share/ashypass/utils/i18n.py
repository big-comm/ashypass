#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# i18n.py - Internationalization support using gettext
#
import gettext
import os

# Determine locale directory (works in AppImage and system install)
locale_dir = '/usr/share/locale'  # Default for system install

# Check if we're in an AppImage
if 'APPIMAGE' in os.environ or 'APPDIR' in os.environ:
    # Running from AppImage
    # i18n.py is in: usr/share/ashypass/utils/i18n.py
    # We need to get to: usr/share/locale
    script_dir = os.path.dirname(os.path.abspath(__file__))  # usr/share/ashypass/utils
    app_dir = os.path.dirname(script_dir)                    # usr/share/ashypass
    share_dir = os.path.dirname(app_dir)                     # usr/share
    appimage_locale = os.path.join(share_dir, 'locale')      # usr/share/locale

    if os.path.isdir(appimage_locale):
        locale_dir = appimage_locale

# Configure the translation text domain for ashypass
gettext.bindtextdomain("ashypass", locale_dir)
gettext.textdomain("ashypass")

# Export _ directly as the translation function
_ = gettext.gettext
