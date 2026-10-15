# Capture plan

1. **Prerequisite:** the Cloud Run deployment is verified and the System status page shows all checks green.
2. **Screen capture:** a scripted Chromium session (Playwright `recordVideo`, 1920×1080) drives the real deployed site through the script's steps, holding each screen long enough for the narration. A pre-created Google test account is signed in once by hand, because Google sign-in can't be automated. Capture is then resumed with that session.
3. **Real model output only:** the scan runs live during capture. If Gemini's wording differs from the narration, the narration is adjusted; the screen is never edited.
4. **Narration:** recorded by Saikrishna from `SCRIPT.md` (QuickTime or any recorder, 48 kHz). An optional fallback is a captions-only cut with on-screen text and no voice.
5. **Assembly (ffmpeg):** title card, then capture clips, the architecture slide and the end card. Narration is mixed in, then exported as H.264 1080p MP4.
6. **Checks before upload:** `ffprobe` duration under 3:00, audio present, file plays.
7. **Publish:** upload to YouTube as Unlisted or Public (the rules accept YouTube, Vimeo or a public Google Drive link). Open it in a signed-out browser to confirm public access. This step needs Saikrishna's account and approval.
