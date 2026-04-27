import logging
import os
import sys
import time
from datetime import datetime

import requests
from dotenv import load_dotenv

LOGIN_URL = "https://doms.iitm.ac.in/domsmba/index.php/admission/login_val"
SHORTLIST_URL = "https://doms.iitm.ac.in/domsmba/index.php/shortlist"
RESULT_URL = "https://doms.iitm.ac.in/domsmba/"
NOT_LIVE_MARKERS = ("cannot be found", "404", "not found")
POLL_INTERVAL_SECONDS = 5 * 60
REQUEST_TIMEOUT = 30

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("doms_check.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("doms_bot")


def send_telegram(token: str, chat_ids: list[str], text: str) -> None:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    for chat_id in chat_ids:
        try:
            r = requests.post(
                url,
                data={"chat_id": chat_id, "text": text, "disable_web_page_preview": "false"},
                timeout=REQUEST_TIMEOUT,
            )
            if r.status_code != 200:
                log.error("Telegram send to %s failed (%s): %s", chat_id, r.status_code, r.text[:200])
            else:
                log.info("Telegram message sent to %s.", chat_id)
        except requests.RequestException as exc:
            log.error("Telegram request error for %s: %s", chat_id, exc)


def login_and_check(email: str, password: str) -> tuple[bool, str]:
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0 Safari/537.36"
            )
        }
    )

    login_resp = session.post(
        LOGIN_URL,
        data={"username": email, "password": password},
        timeout=REQUEST_TIMEOUT,
        allow_redirects=True,
    )
    cookie_names = {c.name for c in session.cookies}
    log.info("Login status=%s cookies=%s", login_resp.status_code, sorted(cookie_names))

    expected = {"ci_session", "BNES_ci_session", "BNIS_x-bni-jas"}
    missing = expected - cookie_names
    if missing:
        log.warning("Missing expected cookies: %s", sorted(missing))

    resp = session.get(SHORTLIST_URL, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    body = resp.text or ""
    body_lower = body.lower()
    log.info("Shortlist status=%s length=%d", resp.status_code, len(body))

    not_live = any(marker in body_lower for marker in NOT_LIVE_MARKERS)
    return (not not_live), body[:200]


def main() -> None:
    load_dotenv()
    email = os.getenv("DOMS_EMAIL")
    password = os.getenv("DOMS_PASSWORD")
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id_raw = os.getenv("TELEGRAM_CHAT_ID", "")
    chat_ids = [c.strip() for c in chat_id_raw.split(",") if c.strip()]

    missing = [k for k, v in {
        "DOMS_EMAIL": email,
        "DOMS_PASSWORD": password,
        "TELEGRAM_BOT_TOKEN": token,
        "TELEGRAM_CHAT_ID": chat_id_raw,
    }.items() if not v]
    if missing:
        log.error("Missing env vars: %s", ", ".join(missing))
        sys.exit(1)

    startup_msg = (
        f"✅ DoMS bot started at {datetime.now().isoformat(timespec='seconds')}. "
        f"Polling every {POLL_INTERVAL_SECONDS // 60} min."
    )
    log.info(startup_msg)
    send_telegram(token, chat_ids, startup_msg)

    notified = False
    while True:
        try:
            is_live, snippet = login_and_check(email, password)
            if is_live and not notified:
                log.info("Page appears LIVE. Sending alert. Snippet=%r", snippet)
                send_telegram(
                    token,
                    chat_ids,
                    f"🎉 IITM DoMS MBA Result is LIVE! Check now: {RESULT_URL}",
                )
                notified = True
            elif is_live:
                log.info("Still live; alert already sent.")
            else:
                log.info("Page not live yet.")
        except requests.RequestException as exc:
            log.error("Check failed: %s", exc)
        except Exception as exc:
            log.exception("Unexpected error: %s", exc)

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
