"""Live request scoring entrypoint — the ONE place real-time scoring happens.

Called by the HTTP server (Phase 4) and ASGI/WSGI middleware (Phase 5).
Loads the trained model once at startup, scores individual requests
against accumulated session history.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from ..collect import DecisionSink
from ..events import DecisionRecorder
from ..features import extract_features
from ..labeler import label_session
from ..model import DEFAULT_MODEL_PATH, BotDetector
from ..parser import LogEntry
from ..scoring import BLOCK_THRESHOLD_DEFAULT, compute_combined_score
from ..signals import Signals
from .state import SessionStateStore

logger = logging.getLogger(__name__)



def _load_model(model_path: str | Path | None = None) -> BotDetector | None:
    """Load the trained model, returning None if it cannot be loaded.

    A None here is not benign: score_request falls back to model_score = 0.0,
    which collapses the blend to the heuristic confidence alone and takes the
    model out of every live blocking decision. That went unnoticed once already
    because this function searched for a filename that never existed in the
    repo and said nothing when it came up empty. Every failure path now logs.

    Args:
        model_path: Path to local model file.
    """
    if model_path is None:
        model_path = DEFAULT_MODEL_PATH
    if not Path(model_path).exists():
        logger.warning(
            "no model at %s - live scoring will run on heuristics only", model_path
        )
        return None
    try:
        detector = BotDetector()
        detector.load(str(model_path))
        return detector
    except (FileNotFoundError, OSError, KeyError, ValueError, json.JSONDecodeError):
        logger.warning(
            "model at %s failed to load - live scoring will run on heuristics only",
            model_path,
            exc_info=True,
        )
        return None


def fail_open_result(ip: str = "") -> dict:
    """The decision payload for a request that could not be scored.

    One builder, not one copy per entrypoint. The keys must match a real
    decision exactly so downstream consumers never special-case a failure --
    `model_loaded` False and the reason string are what say what happened.
    Two hand-maintained copies of this dict drifted the moment a key was added
    to the real decision, and a fail-open payload missing a key the dashboard
    reads fails during an outage, which is the worst time to find it.
    """
    return {
        "ip": ip,
        "label": "human",
        "score": 0.0,
        "model_score": 0.0,
        "heuristic_label": "unknown",
        "heuristic_confidence": 0.0,
        "heuristic_reason": "scoring unavailable",
        "reason": "scoring unavailable",
        "request_count": 0,
        "duration": 0.0,
        "model_loaded": False,
        "model_refused": None,
        # No threshold was consulted, and saying otherwise would let a
        # dashboard plot a bar this decision never met.
        "block_threshold": None,
        "signals": _signal_summary(None),
        # Identified like any other row so the dashboard can key on it, but
        # with no features: nothing was scored, so there is no vector a
        # correction could train on. Feedback refuses these rather than
        # training on a placeholder.
        "id": uuid.uuid4().hex,
        "features": None,
    }


def _signal_summary(signals: Signals | None) -> dict:
    """The signal state worth keeping on a decision record.

    `promoted` is included because the same signal value means different
    things depending on whether it was allowed to decide, and a record that
    omitted it could not explain its own verdict later.
    """
    if signals is None or not signals.resolved:
        return {"resolved": False}
    return {
        "resolved": True,
        "tor_exit": signals.tor_exit,
        "hosting_range": signals.hosting_range,
        "abuse_score": signals.abuse_score,
        "promoted": sorted(signals.promoted),
    }


def _warn_if_degenerate(model, path) -> None:
    """Say so when the model answers the same for every input.

    `compute_combined_score` weights the model at 0.6. A model that emits its
    output bias regardless of input contributes 0.6 of a score that reads as
    independent evidence beside the heuristic and is not.

    Deliberately narrow: this catches TOTAL collapse -- one value for every
    input -- which is what a dead or corrupt model looks like at load time,
    and the runtime counterpart of `BotDetector.check_not_degenerate` at train
    time.

    It does NOT catch the shipped model's condition, and no cheap load-time
    probe can. That model is a two-valued step function that learned one
    leaked column, so it varies with input and passes this check. Output
    diversity does not separate the two either: measured over 200 random
    probes the shipped model spreads WIDER than a correctly trained one
    (range 0.69 vs 0.17), so a diversity threshold would flag the healthy
    model and clear the broken one. Leak detection belongs to
    tests/test_dataset_integrity.py, against the dataset, where it is
    decidable.

    A warning, not a refusal. Which model to serve is an operator's call, and
    the heuristic still carries the other 0.4 -- but "the ML half is inert"
    must not be something you can only discover by reading the weights.
    """
    if model is None:
        return
    probe = [
        [0.0] * BotDetector.NUM_FEATURES,
        [0.5] * BotDetector.NUM_FEATURES,
        [1.0] * BotDetector.NUM_FEATURES,
    ]
    try:
        scores = {round(model.predict(row), 6) for row in probe}
    except Exception:
        logger.debug("degeneracy probe failed for %s", path, exc_info=True)
        return
    if len(scores) == 1:
        logger.warning(
            "model at %s answers identically (%s) for every probe input - it "
            "contributes a constant to every blended score, not a signal",
            path, scores.pop(),
        )


class LiveScorer:
    """Scores requests against live session state.

    Usage:
        store = RedisSessionStateStore(redis_client)
        scorer = LiveScorer(store)
        result = scorer.score_request(entry)
        if result["label"] == "bot":
            return 403
        return 200
    """

    def __init__(
        self,
        store: SessionStateStore,
        model_path: str | Path | None = None,
        block_threshold: float = BLOCK_THRESHOLD_DEFAULT,
        session_ttl: int = 1800,
        short_circuit_label: str = "automated-integration",
        recorder: DecisionRecorder | None = None,
        collector: DecisionSink | None = None,
        threshold_source: Callable[[], float | None] = lambda: None,
        promoted_source: Callable[[], frozenset[str]] = frozenset,
        deployment_id: str | None = None,
        feedback_dir: str | Path | None = None,
        reload_interval: float = 5.0,
    ):
        self._store = store
        self._baseline_path = Path(model_path) if model_path else Path(DEFAULT_MODEL_PATH)
        self._deployment_id = deployment_id
        self._feedback_dir = feedback_dir
        self._reload_interval = reload_interval
        # One shared scorer serves every request thread (server.py sets it as a
        # class attribute), so the swap has to be guarded.
        self._model_lock = threading.Lock()
        self._reloaded_at = 0.0
        self._active_mtime: float | None = None
        self.active_model_path: Path = self._baseline_path
        # Set when a candidate model could not be loaded and the previous one
        # was kept. Surfaced rather than only logged: the failure it replaces
        # was silent, and a silent model is indistinguishable from a working
        # one in every score it produces.
        self.model_refused: str | None = None
        self._model = None
        self._select_model()
        self._block_threshold = block_threshold
        self._session_ttl = session_ttl
        self._short_circuit_label = short_circuit_label
        self._recorder = recorder
        # Separate from the recorder on purpose. The recorder feeds the
        # dashboard from a capped ring; the collector is the durable archive a
        # training set gets built from. They have different lifetimes and
        # different failure costs, so one is not a substitute for the other.
        self._collector = collector
        self._threshold_source = threshold_source
        self._promoted_source = promoted_source

    def _candidate_path(self) -> Path:
        """The model this process should be using right now.

        A deployment model only applies when this process asked for one: a
        scorer started without a deployment id must never pick one up.
        """
        if self._deployment_id is None:
            return self._baseline_path
        from ..training.online_update import deployment_model_path

        candidate = deployment_model_path(self._deployment_id, self._feedback_dir)
        return candidate if candidate.exists() else self._baseline_path

    def _load_active(self):
        """Load whatever `_candidate_path` points at. Test seam."""
        return _load_model(self.active_model_path)

    def _select_model(self) -> None:
        """Pick up a changed model, or keep the one that works.

        Called per request, but the filesystem is only consulted once per
        `reload_interval` -- a stat() on the path nginx waits on is cheap and
        not free, and the file changes a few times a week at most. Same cache
        shape as RedisRuntimeConfig uses for the threshold.
        """
        if (
            self._model is not None
            and (time.monotonic() - self._reloaded_at) < self._reload_interval
        ):
            return

        with self._model_lock:
            # Re-check inside the lock: several request threads can arrive at
            # an expired interval together, and only one should do the load.
            if self._model is not None and (time.monotonic() - self._reloaded_at) < self._reload_interval:
                return

            candidate = self._candidate_path()
            try:
                mtime = candidate.stat().st_mtime
            except OSError:
                mtime = None
            if (
                self._model is not None
                and candidate == self.active_model_path
                and mtime == self._active_mtime
            ):
                self._reloaded_at = time.monotonic()
                return

            previous_path = self.active_model_path
            self.active_model_path = candidate
            loaded = self._load_active()
            if loaded is None and self._model is not None:
                # Decision 6A. The old behavior here was to fall through to
                # model_score 0.0, which collapses every blend to the heuristic
                # alone and produces in-range, meaningless scores forever after
                # -- with nothing anywhere saying why.
                self.model_refused = str(candidate)
                self.active_model_path = previous_path
                logger.error(
                    "model at %s could not be loaded - refused the swap and kept %s",
                    candidate, previous_path,
                )
                self._reloaded_at = time.monotonic()
                return

            self._model = loaded
            self._active_mtime = mtime
            self.model_refused = None
            _warn_if_degenerate(loaded, candidate)
            # Stamped after the load, not before: the interval measures time
            # since a COMPLETED check, so a slow or failed load does not buy
            # itself a free window. It also makes the double-check above
            # meaningful -- threads that queued on the lock while this ran see
            # a fresh timestamp and skip the work instead of repeating it.
            self._reloaded_at = time.monotonic()

    @property
    def model_loaded(self) -> bool:
        """Whether scores include a model contribution at all."""
        return self._model is not None

    def score_request(self, entry: LogEntry) -> dict:
        """Score a single request against accumulated session state.

        Returns the full decision, not just the verdict:

            {
                "ip": str,
                "label": "bot" | "human",
                "score": float,           # the blended score the decision used
                "model_score": float,     # what the model alone said
                "heuristic_label": str,   # what the rules alone said
                "heuristic_confidence": float,
                "heuristic_reason": str,
                "request_count": int,
                "duration": float,        # seconds spanned by retained history
                "model_loaded": bool,
            }

        The breakdown is the point. A single blended float tells an operator
        that a customer was blocked but not whether the rules or the model
        drove it, which is exactly what you need to tune a threshold. It is
        also how a dead model stays visible: model_score pinned at 0.0 across
        every response is a symptom you can see.
        """
        # One atomic call: append, cap, refresh TTL, and read back the session
        # to score. The old get/mutate/set pair lost concurrent appends from
        # the same actor, which undercounted request_count under exactly the
        # load the rate and timing rules are there to catch.
        snapshot = self._store.record_request(
            entry.ip,
            entry.user_agent,
            entry,
            ttl_seconds=self._session_ttl,
        )
        session = snapshot.session
        signals = self._promote(snapshot.signals)
        self._select_model()

        h_label, h_conf, h_reason = label_session(session, signals)  # type: ignore[arg-type]

        # Computed before the short-circuit, not after: an
        # automated-integration verdict is still a verdict an operator can
        # disagree with, and a correction needs the vector the decision was
        # actually made from. Roughly 2ms and the dominant per-request cost, so
        # skipped entirely when nothing consumes it -- no model and no recorder
        # means no consumer.
        features = None
        if self._model is not None or self._recorder is not None:
            features = extract_features(session)  # type: ignore[arg-type]

        # Short-circuit for automated integrations
        if h_label == self._short_circuit_label:
            return self._result(
                session,
                label="human",
                score=0.0,
                model_score=0.0,
                h_label=h_label,
                h_conf=h_conf,
                h_reason=f"automated-integration (not blocked): {h_reason}",
            )

        model_score = (
            self._model.predict(features)
            if self._model is not None and features is not None
            else 0.0
        )

        threshold = self._threshold()
        combined = compute_combined_score(h_label, h_conf, model_score)
        # A score sitting exactly on the bar has not cleared it. At a 0.5
        # threshold that number is the neutral verdict itself ("no strong
        # signals either way" caps at exactly 0.5), and spec AC#7 says an
        # unknown visitor with no history is allowed by default. Strict `>`
        # also makes threshold 1.0 a real never-block escape hatch.
        label = "bot" if combined > threshold else "human"

        return self._result(
            session,
            label=label,
            score=combined,
            threshold=threshold,
            model_score=model_score,
            h_label=h_label,
            h_conf=h_conf,
            h_reason=h_reason,
            signals=signals,
            features=features,
        )

    def _promote(self, signals: Signals) -> Signals:
        """Attach the deployment's promotion list to this actor's signals.

        Promotion is deployment configuration, not per-actor data, so the store
        does not carry it. Read per request, like the threshold, so an operator
        can promote a signal from the dashboard without restarting and dropping
        every in-flight session. A failing source promotes nothing, which keeps
        an unreachable config store from silently enforcing a signal nobody
        approved.
        """
        if not signals.resolved:
            return signals
        try:
            promoted = self._promoted_source()
        except Exception:
            logger.exception("promotion source failed, treating every signal as observe-only")
            return signals
        return replace(signals, promoted=promoted) if promoted else signals

    def _threshold(self) -> float:
        """The threshold this request is judged against.

        Read per request so an operator can move it from the dashboard without
        restarting and dropping every in-flight session. A source that fails
        falls back to the configured value rather than changing the verdict:
        an unreachable config store must not silently start blocking everyone
        or stop blocking anyone.
        """
        try:
            override = self._threshold_source()
        except Exception:
            logger.exception("threshold source failed, using configured threshold")
            return self._block_threshold
        return self._block_threshold if override is None else override

    def _result(
        self,
        session,
        *,
        label: str,
        score: float,
        model_score: float,
        h_label: str,
        h_conf: float,
        h_reason: str,
        threshold: float | None = None,
        signals: Signals | None = None,
        features: list[float] | None = None,
    ) -> dict:
        """Assemble the decision payload. One place, so the short-circuit and
        the scored path cannot report different shapes — and so recording
        cannot miss one of them."""
        result = {
            "ip": session.ip,
            "label": label,
            "score": score,
            "model_score": model_score,
            "heuristic_label": h_label,
            "heuristic_confidence": h_conf,
            "heuristic_reason": h_reason,
            "request_count": session.request_count,
            "duration": session.duration,
            "model_loaded": self.model_loaded,
            # Set when a candidate model would not load and the previous one
            # was kept. It travels on the decision because that is the only
            # channel the dashboard reads: the failure it replaces was
            # completely silent, and a silently dead model is indistinguishable
            # from a working one in every score it produces.
            "model_refused": self.model_refused,
            # Which bar this decision was actually judged against — without it
            # a dashboard cannot tell a changed threshold from a changed score.
            "block_threshold": self._block_threshold if threshold is None else threshold,
            # Kept for callers reading the old four-key shape.
            "reason": h_reason,
            # The observe half of observe-until-promoted: an unpromoted signal
            # decides nothing, but it still travels into the record so an
            # operator can see what it would have done before enforcing it.
            "signals": _signal_summary(signals),
            # Identifies this decision so an operator's later correction can
            # name it. Without one, a dashboard row is an anonymous blob in a
            # LIST and there is nothing to point at.
            "id": uuid.uuid4().hex,
            # The vector this decision was actually made from. Kept here rather
            # than recomputed at feedback time, because the live session is a
            # 200-entry sliding window on a 1800s TTL: by the time anyone
            # reviews a block, the inputs that produced it are gone.
            "features": features,
        }
        self._record(result)
        return result

    def _record(self, result: dict) -> None:
        """Tee the decision to the dashboard recorder, if there is one.

        Every exception is swallowed. Recording exists so an operator can see
        what happened; blocking exists so the site stays up. nginx turns any
        non-2xx/401/403 from /check into a 500 for the visitor, so a Redis blip
        in the recorder must not become an outage — the same fail-open reasoning
        as server.py's scoring guard.
        """
        if self._recorder is not None:
            try:
                self._recorder.record(result)
            except Exception:
                logger.exception("decision recording failed, continuing")

        if self._collector is not None:
            try:
                self._collector.record(result)
            except Exception:
                logger.exception("decision collection failed, continuing")
