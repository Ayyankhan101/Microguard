# ruff: noqa
# Vulture whitelist: confirmed false positives (tested utilities / framework
# method overrides that vulture can't detect via static analysis). Not
# executed or imported by the package — parsed by vulture only, so this file
# is excluded from ruff (see file-level noqa above) and mypy (see mypy.ini).
from microguard.model import BotDetector
from microguard.parser import LogEntry
from microguard.features import _url_depth, _url_width
from microguard.training.groundtruth import GroundTruthRule, label_line
from microguard.live.middleware import MicroguardASGI, MicroguardWSGI
from microguard.live.server import CheckHandler

BotDetector.sigmoid
LogEntry.to_dict

# Asserted in tests/test_events.py; the Redis side uses ZCARD for the same
# property, so nothing in the package calls this by name.
from microguard.events import InMemoryDecisionRecorder
InMemoryDecisionRecorder.tracked_ip_count
_url_depth
_url_width
GroundTruthRule.id
GroundTruthRule.sensitivity
label_line

# Public middleware entrypoints — used from README + tests, not from the package.
MicroguardASGI
MicroguardWSGI

# BaseHTTPRequestHandler dispatch + override; called by http.server, not by us.
CheckHandler.do_GET
CheckHandler.do_POST
CheckHandler.log_message

# socketserver.ThreadingMixIn reads self.daemon_threads in process_request;
# run_server only writes it, so vulture sees a write with no read.
_.daemon_threads

# NoRedirect.redirect_request is a nested class inside scanner.probe_url,
# so it can't be imported here — reference it via attribute access instead.
_.redirect_request

# FastAPI route handlers and pydantic config — registered via decorators and
# read by pydantic, never called by name from the package.
from microguard.dashboard import api_health, api_live, api_model, api_scan, app as dashboard_app

dashboard_app.create_app
api_health.health
api_scan.list_samples
api_scan.scan
api_scan.scan_upload
api_scan.export
api_model.describe_model
api_model.evaluate
api_live.stats
api_live.events
api_live.stream
api_live.submit_feedback
api_live.read_config
api_live.write_config

# FastAPI @app.middleware registers this by decoration; it is never called by name.
_.check_token
_.model_config

# The read-back half of the collection archive. Nothing in the package calls
# it yet -- the writer runs in `serve`, and the reader is what a dataset
# builder will use once observe-only collection has produced rows worth
# building from. Tested in tests/test_collect.py.
from microguard import collect

collect.load_collected
