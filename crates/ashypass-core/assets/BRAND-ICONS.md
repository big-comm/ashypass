# Brand icons

`brand-icons.json.gz` holds the brand icons shown beside verification codes
(`ashypass_core::brand_icons`): **Simple Icons 16.35.0**
(<https://simpleicons.org>), released under **CC0-1.0**.

Each entry keeps the brand's id, names and aliases, colour and SVG path; the
apps draw the mark on a square of the brand's colour. It is matched to a
code's name on the device: no name is sent anywhere.

The icons are trademarks of their owners. Their use here only identifies the
service a code belongs to and implies no endorsement; see Simple Icons'
disclaimer: <https://github.com/simple-icons/simple-icons/blob/develop/DISCLAIMER.md>.

To update: see `tools/make_brand_icons.py`, then change the version above.
