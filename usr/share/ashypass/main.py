#!/usr/bin/env python3
"""
Ashy Pass - Main Application
Modern password generator and encrypted password vault
"""

import sys
import logging
import gi

gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')

from gi.repository import Gtk, Adw, Gio, GLib

from core.config import APP_ID, APP_NAME, APP_VERSION, ensure_directories
from core.database import Database
from utils.i18n import _
from ui.window import MainWindow

logger = logging.getLogger(__name__)


class AshyPassApplication(Adw.Application):
    """Main application class"""

    def __init__(self):
        super().__init__(
            application_id=APP_ID,
            flags=Gio.ApplicationFlags.DEFAULT_FLAGS
        )
        logger.debug("Application ID: %s", APP_ID)
        
        self.database = None
        self.window = None
        
        # Setup actions
        self.create_action("quit", lambda *_: self.quit(), ["<primary>q"])
        self.create_action("about", self.on_about_action)
        
        # Action with parameter for toast messages
        action = Gio.SimpleAction.new("show-toast", GLib.VariantType.new("s"))
        action.connect("activate", self.on_show_toast)
        self.add_action(action)
    
    def do_activate(self):
        """Called when the application is activated"""
        # Ensure directories exist
        ensure_directories()
        
        # Initialize database
        if not self.database:
            self.database = Database()
            self.database.connect()
            self.database.initialize()
            logger.debug("Database initialized")
        
        # Create window if it doesn't exist
        if not self.window:
            self.window = MainWindow(self, self.database)

        self.window.present()
    
    def on_shutdown(self, app):
        """Called when the application is shutting down"""
        if self.database:
            self.database.close()
    
    def create_action(self, name, callback, shortcuts=None):
        """Create a simple application action"""
        action = Gio.SimpleAction.new(name, None)
        action.connect("activate", callback)
        self.add_action(action)
        
        if shortcuts:
            self.set_accels_for_action(f"app.{name}", shortcuts)
        
        return action
    
    def on_about_action(self, *args):
        """Show about dialog"""
        about = Adw.AboutDialog()
        about.set_application_name(APP_NAME)
        about.set_application_icon("ashypass")
        about.set_version(APP_VERSION)
        about.set_developer_name("Big Community")
        about.set_license_type(Gtk.License.MIT_X11)
        about.set_comments(_("Modern password generator and encrypted password vault"))
        about.set_website("https://github.com/big-comm")
        about.set_issue_url("https://github.com/big-comm/ashypass/issues")
        about.add_credit_section(
            _("Contributors"),
            [_("Big Community Apps")]
        )

        about.present(self.window)
    
    def on_show_toast(self, action, parameter):
        """Show toast notification"""
        if self.window:
            message = parameter.get_string()
            self.window.show_toast(message)


def main():
    """Main entry point"""
    logging.basicConfig(
        level=logging.DEBUG if "--debug" in sys.argv else logging.WARNING,
        format="%(levelname)s: %(name)s: %(message)s",
    )

    try:
        Adw.init()
        app = AshyPassApplication()
        # Filter out --debug before passing to GLib
        gtk_argv = [a for a in sys.argv if a != "--debug"]
        return app.run(gtk_argv)
    except Exception as e:
        logger.error("Error starting application: %s", e, exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
