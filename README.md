# DoMS Result Notifier Bot

Polls the IITM DoMS MBA shortlist page every 5 minutes and pings you on Telegram the moment it goes live.

## How it works

1. Logs in to `https://doms.iitm.ac.in/domsmba/index.php/admission/login_val` with your credentials and captures `ci_session`, `BNES_ci_session`, and `BNIS_x-bni-jas` cookies.
2. Uses those cookies to GET `https://doms.iitm.ac.in/domsmba/index.php/shortlist`.
3. If the response body contains `cannot be found`, `404`, or `not found`, the page is treated as not live yet.
4. Otherwise it sends a Telegram alert and stops re-alerting (one notification per run).
5. Repeats every 5 minutes with a fresh login each time.

## Setup

```bash
pip install requests python-dotenv
cp .env.example .env
# edit .env with your real values
python doms_bot.py
```

### Getting Telegram credentials

1. Talk to [@BotFather](https://t.me/BotFather) on Telegram, run `/newbot`, follow the prompts, and copy the token into `TELEGRAM_BOT_TOKEN`.
2. Send your new bot any message (so it has permission to message you back).
3. Open `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates` in a browser and copy the numeric `chat.id` into `TELEGRAM_CHAT_ID`.

## Files

- `doms_bot.py` — the poller.
- `.env` — your secrets (not committed).
- `.env.example` — template.
- `doms_check.log` — append-only log of every check.

## Running it as a long-lived process

On Windows, the simplest option is to leave it running in a terminal. For unattended use, wrap it with `nssm`, Task Scheduler, or a small `pythonw` shortcut. On Linux, a systemd unit or `tmux`/`screen` session works well.

## Notes

- The script intentionally creates a new `requests.Session` every cycle so stale cookies can't mask a freshly published page.
- Network errors are caught and logged; the loop keeps going.
- Once an alert fires, it won't re-fire in the same run — restart the script if you want to re-arm it.
