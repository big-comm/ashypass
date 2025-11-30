#!/usr/bin/env python3
"""
Ashy Pass - Main Application
Modern password generator and encrypted password vault
"""

import sys
import gi

gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')

from gi.repository import Gtk, Adw, Gio, GLib

from core.config import APP_ID, APP_NAME, ensure_directories
from core.database import Database
from utils.i18n import _
from ui.window import MainWindow


class AshyPassApplication(Adw.Application):
    """Main application class"""
    
    def __init__(self):
        print("Initializing AshyPassApplication...")
        super().__init__(
            application_id=APP_ID,
            flags=Gio.ApplicationFlags.DEFAULT_FLAGS
        )
        print(f"Application ID: {APP_ID}")
        
        self.database = None
        self.window = None
        
        # Setup actions
        self.create_action("quit", lambda *_: self.quit(), ["<primary>q"])
        self.create_action("about", self.on_about_action)
        
        # Action with parameter for toast messages
        action = Gio.SimpleAction.new("show-toast", GLib.VariantType.new("s"))
        action.connect("activate", self.on_show_toast)
        self.add_action(action)
        print("AshyPassApplication initialized")
    
    def do_activate(self):
        """Called when the application is activated"""
        print("do_activate called!")
        
        # Ensure directories exist
        ensure_directories()
        print("Directories ensured")
        
        # Initialize database
        if not self.database:
            print("Initializing database...")
            self.database = Database()
            self.database.connect()
            self.database.initialize()
            print("Database initialized")
        
        # Create window if it doesn't exist
        if not self.window:
            print("Creating main window...")
            self.window = MainWindow(self, self.database)
            print("Window created")
        
        print("Presenting window...")
        self.window.present()
        print("Window presented!")
    
    def on_shutdown(self, app):
        """Called when the application is shutting down"""
        print("Shutting down...")
        # Close database connection
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
        about.set_version("1.0.0")
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
    try:
        print("Starting Ashy Pass...")
        
        # Initialize libadwaita
        Adw.init()
        print("Libadwaita initialized")
        
        app = AshyPassApplication()
        print("Application created, running...")
        exit_code = app.run(sys.argv)
        print(f"Application exited with code: {exit_code}")
        return exit_code
    except Exception as e:
        print(f"Error starting application: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
