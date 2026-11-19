# Changelog

## 0.1.1 (2026-11-18)

A same-day follow-up to 0.1.0. Private groups can now carry images, voice notes and files, up to 1 MiB each, without changing the iOS group wire format.

- Each attachment is split into chunks and sealed inside ordinary signed, encrypted group messages. An iPhone in the group ignores the extra data and shows the caption as a text line (one per chunk); ghostchat reassembles the chunks and shows one file.
- Files save through the same validated path as private files: MIME allow-list, magic bytes, 1 MiB cap, and a whole-file SHA-256 digest check.
- A chunked group send reports one continuous 0-100% progress line. A partial file expires after 10 minutes without a new chunk, with one notice.
- The 16-member cap and the nearby-Bluetooth-only mesh are unchanged; group media is live-only and has no backfill or offline inbox.

The rest of 0.1.0 is unchanged. Installing over 0.1.0 keeps your identity, favorites and groups.

## 0.1.0 (2026-11-18)

First public release of ghostchat 🧙‍♀️, an independent Windows and Linux client for the bitchat Bluetooth mesh. Not official, and not affiliated with the bitchat project.

**What you get**

- A real mesh peer: `#mesh`, relaying with the same timing and TTL rules as iOS, fragments and gossip sync. Ghostchat connects out to phones and, where the adapter allows it, lets phones connect in.
- Private messages with Noise end-to-end encryption, delivered and read receipts, a 24 h encrypted outbox, a Nostr fallback for mutual favorites, and a sealed copy a trusted peer can carry when no relay has accepted the message.
- Location channels, files and voice notes, opt-in Tor, the tray, notifications that never show message text, QR verification and a panic wipe.
- A per-user Windows setup, a Linux `.deb`, and portable zip/tarball downloads. Closing the window hides ghostchat in the notification area; **Quit** on the tray icon is what stops it.
- `ghostchat --relay`: a headless relay node for a PC or Linux box left on.
- The full list is in [README.md](README.md#features).

**Known issues**

- Two phones relaying through the PC has been shown once with iOS phones; not yet with Android.
- Windows sometimes does not start advertising, so the footer stays "central-only" until you quit and open ghostchat again. Phones can still be reached, because ghostchat connects out to them.
- Linux: the GATT server (phones connecting in) and the relay user service build and pass tests, but have not been run with a phone on a real Linux desktop. Reports are welcome ([CONTRIBUTING.md](CONTRIBUTING.md#linux-lab)).
- A PC cannot discover an iPhone while bitchat is in the background there. Open bitchat on the phone once; the link then keeps working in the background.
- Phones that only see each other over Wi-Fi Aware do not appear.
- One copy per PC: the window app and `--relay` share the Bluetooth adapter, so a second copy refuses to start.
- Windows: after quitting and restarting ghostchat, Windows can keep a stuck connection to the phones, so they never reappear. ghostchat spots this and offers "reset Bluetooth", which turns the radio off and on and restarts ghostchat (headphones drop for a few seconds). The same button is on the Debug tab, and `ghostchat --ble-links` shows whether Windows still holds a phone. A headless `--relay` on Windows resets once by itself.
- Windows: the binary is unsigned, so the first start warns you. The browser may call the zip uncommon, SmartScreen says "Windows protected your PC" (**More info → Run anyway**), and Defender may say "Risky action blocked" if the folder is on the Desktop or in OneDrive (**Protection history → Allow on device**). Check the hash below first. A match means this is the file from this release. Do not turn Defender off. Steps: [docs/WINDOWS.md](docs/WINDOWS.md#unsigned-download-smartscreen-and-defender) and [README.md](README.md#first-run-the-warnings).

More limits, unchanged between releases: [README.md](README.md#honest-limits).

**Check your download**

- The archive or installer: its hash is in `SHA256SUMS.txt` on this release page.
- Windows: `Get-FileHash ghostchat.exe` must match `ghostchat.exe.sha256`.
- Linux: `sha256sum -c ghostchat.sha256`, or compare the `.deb` with its line in `SHA256SUMS.txt` and check `dpkg -s ghostchat` after installing it.
