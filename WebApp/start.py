"""Production startup using Flask's built-in server (dev) or Waitress (prod).

Usage:
  python start.py              # dev — hot-reload on localhost:5000
  python start.py --prod       # production — waitress on 0.0.0.0:5000
  python start.py --port 8080  # custom port

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
args = parser.parse_args()

sys.path.insert(0, os.path.dirname(__file__))

if args.prod:
    try:
        from waitress import serve
        from app import app
        print(f"Starting DC Anomaly Agent web UI (waitress) on {args.host}:{args.port}")
        serve(app, host=args.host, port=args.port, threads=4)
    except ImportError:
        print("waitress not installed — run: pip install waitress")
        print("Falling back to Flask development server.")
        from app import app
        app.run(host=args.host, port=args.port, debug=False)
else:
    from app import app
    app.run(host=args.host, port=args.port, debug=True)
