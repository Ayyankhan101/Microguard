"""Benchmarks that measure microguard against baselines on traffic it did not label.

Kept outside the `microguard` package on purpose: this code imports tools the
package must never depend on (Playwright, scikit-learn, remotezip) and is not
part of CI's `pytest tests/` run or its coverage gate. See README.md here and
PREREGISTRATION.md for what is measured and how each result is judged.
"""
