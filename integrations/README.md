# Helix in other tools

Both integrations call Helix as a library (`osint.api.scan`), so they report
what a Helix scan reports: accounts confirmed by the control probe, never a
site's bare "found". Install Helix first (`pipx install helix-osint`, or
`pip install helix-osint` into the Python the other tool uses).

## Maltego

`maltego/helix_transform.py` is a local transform. It takes an Alias entity
and returns one Website entity per confirmed account.

1. In Maltego: Transforms, New Local Transform.
2. Input entity type: Alias (`maltego.Alias`).
3. Command: the Python that has Helix installed. Parameters:
   the full path of `helix_transform.py`. Add `all` after it to scan every
   source instead of the built-in sites.
4. Run it on an Alias. Each result carries the profile address, the identity
   grade and the source database.

Sites that gave no clear answer are written to the transform's message
panel with the count, so an empty result is not read as "no accounts".

## SpiderFoot

`spiderfoot/sfp_helix.py` is a SpiderFoot module. Copy it into SpiderFoot's
`modules/` folder and restart SpiderFoot. It watches `USERNAME` events and
produces `ACCOUNT_EXTERNAL_OWNED` events (and `SOCIAL_MEDIA` for social
sites), the same event types SpiderFoot's own account finder uses.

Options: `sources` (`builtin` or `all`) and `purpose`, which is passed to
Helix.

## Tested how

Both files are tested against the formats the two tools document (the
transform's XML reply, the module's event types), with a stand-in for the
tool. Neither has yet been run inside Maltego or SpiderFoot itself. If one
misbehaves there, please open an issue with the tool's version.
