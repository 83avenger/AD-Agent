"""Production startup using Flask's built-in server (dev) or Waitress (prod).

Usage:
  python start.py                      # dev - hot-reload on localhost:5000
  python start.py --prod               # production - waitress on 0.0.0.0:5000
  python start.py --prod --port 8080   # custom port
  python start.py --prod --allow-dev-fallback   # last resort if waitress is unavailable

On Windows (production), run under the same gMSA that runs the scan tasks,
or under a dedicated service account with the least privilege required.
Bind to localhost and front with IIS reverse proxy for TLS termination.
"""

import argparse
import os
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--prod",  action="store_true", help="Use waitress WSGI server")
parser.add_argument("--host",  default=os.environ.get("HOST", "0.0.0.0"))
parser.add_argument("--port",  type=int, default=int(os.environ.get("PORT", 5000)))
# Production previously fell back to the single-threaded Flask dev server when waitress
# was missing, printing a warning that is invisible in a background Scheduled Task - a
# silent downgrade to a server that wedges under the dashboard's auto-refresh plus a few
# open tabs. Prod now fails loudly instead (non-zero exit, so the task shows failure and
# the watchdog reacts), unless the operator explicitly opts into the fallback.
parser.add_argument("--allow-dev-fallback", action="store_true",
                    help="If waitress is unavailable in --prod, run the Flask dev server instead of exiting.")
args = parser.parse_args()

sys.path.insert(0, os.path.dirname(__file__))

if args.prod:
    try:
        from waitress import serve
    except ImportError:
        if not args.allow_dev_fallback:
            sys.stderr.write(
                "FATAL: waitress is not installed, so --prod cannot start a production server.\n"
                "       Install it:  pip install waitress\n"
                "       (offline: pip install --no-index --find-links <wheels> waitress)\n"
                "       Or, as a last resort, re-run with --allow-dev-fallback to use the\n"
                "       single-threaded Flask dev server (not suitable for real use).\n"
            )
            sys.exit(1)
        from app import app
        sys.stderr.write("WARNING: waitress unavailable - falling back to Flask dev server (--allow-dev-fallback).\n")
        app.run(host=args.host, port=args.port, debug=False, threaded=True)
    else:
        from app import app
        # Thread count scales how many concurrent requests the UI can serve (dashboard
        # auto-refresh + several tabs + scan-status polling add up); tunable via env.
        threads = int(os.environ.get("WEB_THREADS", "8"))
        print(f"Starting DC Anomaly Agent web UI (waitress, {threads} threads) on {args.host}:{args.port}")
        serve(app, host=args.host, port=args.port, threads=threads)
else:
    from app import app
    app.run(host=args.host, port=args.port, debug=True)
