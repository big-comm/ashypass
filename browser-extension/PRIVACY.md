# Ashy Pass browser extension — Privacy policy

*Applies to the Ashy Pass extension for Chrome-family browsers and Firefox.
Last updated: October 2026.*

The Ashy Pass extension does not collect, sell or share any data. It has no
server, no analytics, no advertising and no remote code.

## What the extension works with

The extension is a companion to the Ashy Pass password manager installed on
the same computer. It talks only to that application, through the browser's
native messaging (a local connection between the browser and a program on
the computer). Nothing it handles leaves the computer through the extension.

- **Address of the current tab.** Read when you open the extension or use
  a login field, to show the logins saved for that site. It is sent to the
  local Ashy Pass application, which decides which logins belong to the site.
- **Logins and verification codes.** When you choose Fill or Copy, the
  extension asks the application for that one login (or code) and uses it
  right away. Fill only works on the site the login belongs to; the
  application checks this.
- **Master password or PIN.** When the vault is locked, what you type in the
  extension is passed to the local application to unlock it, and not kept.
- **Logins you add or edit** in the extension are saved by the application,
  in your vault.
- **Site icons** come from the icons the application already keeps; the
  extension never downloads anything.

## What the extension stores

Only its own preferences, in the browser's extension storage: the password
generator options, whether the suggestions in login fields are on, whether
it turned off the browser's own password saving for you, and whether you
dismissed a tip. No passwords, codes, addresses or browsing
history are stored by the extension.

## Clipboard

Copy puts the username, password or code on the clipboard only when you
click it.

## Permissions

- *Native messaging*: to talk to the Ashy Pass application on this computer.
- *Access to websites*: to show the Ashy Pass button and suggestions in
  login fields and to fill them.
- *Scripting* and *active tab*: to fill the login into the page you are on.
- *Clipboard write*: for the Copy buttons.
- *Storage*: for the preferences above.
- *Privacy* (optional, asked only if you choose it): to turn off the
  browser's own password saving, so it does not compete with Ashy Pass.

## Contact

Questions or concerns: <https://github.com/big-comm/ashypass/issues>
