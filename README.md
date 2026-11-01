# BNOTIFY group receiver

Standalone service for the unused BNOTIFY channel only. No connection to the existing Facebook project or Double B Agent service.

Render: Python 3, build `python --version`, start `python server.py`, health check `/healthz`.
Set new service environment variables `LINE_CHANNEL_SECRET` (BNOTIFY only) and `LINE_PAIRING_CODE` (random one-time phrase). No access token required for this receiver.

After deploying and configuring BNOTIFY's new webhook, send the pairing phrase in the admin group. Signed matching group messages emit only `BNOTIFY_PAIRED_GROUP=...` in the new service logs. Other chat messages are discarded. Clear pairing code after retrieving the group ID. Signed empty verification events return 200 while configured.

The receiver does not send notifications. WordPress order delivery must be configured separately with BNOTIFY credentials and the paired group ID. No secrets belong in Git.