#!/usr/bin/env bash
# One-shot demo: simulated network + monitoring engine + bot, all logging to
# the console. Alerts go to Telegram if TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID
# are set; otherwise they are only printed and recorded in alerts.jsonl.
set -e
cd "$(dirname "$0")"

echo "== 1/3 starting simulated network (agents on 127.0.0.1:1161-1166) =="
python3 agent_sim.py &
AGENTS=$!
sleep 2

echo "== 2/3 starting monitoring engine =="
if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
    python3 monitor.py &
else
    python3 monitor.py --no-telegram &
fi
MONITOR=$!

if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
    echo "== 3/3 starting interactive bot =="
    python3 bot.py &
    BOT=$!
else
    echo "== 3/3 skipped bot (set TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID) =="
    BOT=""
fi

trap 'kill $AGENTS $MONITOR $BOT 2>/dev/null' EXIT
echo "Demo running. Incidents fire at ~45s / 80s / 115s / 140s / 165s. Ctrl+C to stop."
wait
