"""
ml_analysis.py
---------------
Machine-learning fallback detection, used when the blacklist stage
(PhishTank / whitelist / VirusTotal) is inconclusive.

Beyond the raw PHISHING/LEGITIMATE label and confidence, this module
surfaces *why* the model might have decided what it did: whether the
sender address looks suspicious, whether the subject uses urgency
language, how many links were found, the sender's domain, and - when the
underlying model exposes it - which learned features weighed most heavily
on the prediction.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional

import joblib
import pandas as pd

logger = logging.getLogger(__name__)

MODEL_PATH = "phishing_email_model_fixed.pkl"

_SUSPICIOUS_SENDER_KEYWORDS = ("support", "security", "admin", "service", "help", "verify", "account")
_URGENCY_KEYWORDS = (
    "urgent", "immediately", "act now", "verify your account", "suspended",
    "expire", "expires", "final notice", "action required", "limited time",
    "your account will be", "click here", "confirm your", "password will expire",
)

_model_cache = None


@dataclass
class MLExplanation:
    """Everything needed to present the ML fallback's reasoning to a user."""

    prediction: str = "ERROR"          # "PHISHING", "LEGITIMATE", or "ERROR"
    confidence: float = 0.0            # 0-100
    suspicious_sender: bool = False
    urgent_subject: bool = False
    url_count: int = 0
    sender_domain: str = ""
    top_features: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def explain(self) -> str:
        lines = [
            f"ML prediction: {self.prediction} ({self.confidence:.1f}% confidence)",
            f"  Suspicious sender pattern: {'yes' if self.suspicious_sender else 'no'}",
            f"  Urgent/pressure language in subject: {'yes' if self.urgent_subject else 'no'}",
            f"  URLs found: {self.url_count}",
            f"  Sender domain: {self.sender_domain or 'unknown'}",
        ]
        if self.top_features:
            lines.append(f"  Top contributing model features: {', '.join(self.top_features)}")
        if self.error:
            lines.append(f"  Note: {self.error}")
        return "\n".join(lines)


def _load_model():
    """Load and cache the trained pipeline so repeated calls don't re-read disk."""
    global _model_cache
    if _model_cache is None:
        _model_cache = joblib.load(MODEL_PATH)
    return _model_cache


def _looks_like_suspicious_sender(sender: str) -> bool:
    sender_lower = (sender or "").lower()
    return any(keyword in sender_lower for keyword in _SUSPICIOUS_SENDER_KEYWORDS)


def _looks_urgent(subject: str) -> bool:
    subject_lower = (subject or "").lower()
    return any(keyword in subject_lower for keyword in _URGENCY_KEYWORDS)


def _top_model_features(model, top_n: int = 5) -> List[str]:
    """Best-effort extraction of the model's most important learned features.

    Only works for pipelines exposing ``feature_importances_`` (e.g. our
    RandomForest) with a ColumnTransformer preprocessor step; returns an
    empty list rather than raising if the pipeline shape doesn't match.
    """
    try:
        classifier = model.named_steps.get("classifier")
        preprocessor = model.named_steps.get("preprocessor")
        if classifier is None or preprocessor is None:
            return []
        if not hasattr(classifier, "feature_importances_"):
            return []

        feature_names: List[str] = []
        for name, transformer, _cols in preprocessor.transformers_:
            if hasattr(transformer, "get_feature_names_out"):
                try:
                    feature_names.extend(
                        f"{name}:{f}" for f in transformer.get_feature_names_out()
                    )
                    continue
                except Exception:
                    pass
            # Fall back to a generic label so lengths still line up loosely.
            feature_names.append(name)

        importances = classifier.feature_importances_
        if len(feature_names) != len(importances):
            # Lengths won't always line up perfectly across custom
            # transformers; don't guess incorrectly, just skip this extra.
            return []

        ranked = sorted(zip(feature_names, importances), key=lambda pair: pair[1], reverse=True)
        return [name for name, _importance in ranked[:top_n]]
    except Exception as exc:
        logger.debug("Could not extract top model features: %s", exc)
        return []


def ml_detection_check(
    sender: str,
    subject: str,
    body: str,
    url_count: int,
) -> MLExplanation:
    """Run the ML fallback model and build a full explanation of the result.

    Never raises: any failure loading the model or predicting is captured
    in the returned ``MLExplanation.error`` field with prediction "ERROR".

    Args:
        sender: The sender's email address.
        subject: The email subject line.
        body: The visible body text.
        url_count: Number of (validated) URLs found in the email.

    Returns:
        A populated MLExplanation.
    """
    explanation = MLExplanation(
        suspicious_sender=_looks_like_suspicious_sender(sender),
        urgent_subject=_looks_urgent(subject),
        url_count=url_count,
        sender_domain=sender.split("@")[-1].lower() if sender and "@" in sender else "",
    )

    try:
        model = _load_model()
        input_row = pd.DataFrame([{
            "subject": subject or "",
            "body": body or "",
            "sender": sender or "",
            "urls": url_count,
        }])

        prediction = model.predict(input_row)[0]
        probabilities = model.predict_proba(input_row)[0]
        confidence = float(max(probabilities)) * 100

        explanation.prediction = "PHISHING" if prediction == 1 else "LEGITIMATE"
        explanation.confidence = confidence
        explanation.top_features = _top_model_features(model)

    except FileNotFoundError:
        explanation.error = f"Model file not found at '{MODEL_PATH}'."
        logger.warning(explanation.error)
    except Exception as exc:
        explanation.error = f"ML prediction failed: {exc}"
        logger.warning(explanation.error)

    return explanation
