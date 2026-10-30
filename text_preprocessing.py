"""Text preprocessing shared by training (scikit-learn) and serving (ONNX Runtime).

The ONNX graph that skl2onnx produces for our TfidfVectorizer(analyzer="char")
does not reproduce scikit-learn's preprocessing: it doesn't collapse runs of
whitespace (scikit-learn's char analyzer turns them into one space before
building n-grams), and its lowercasing is locale-dependent. Unfixed, an attack
padded with extra spaces scored 0.58 under ONNX against 0.98 under
scikit-learn. So the API applies scikit-learn's exact preprocessing in Python
before calling ONNX Runtime, and the exported model records which
preprocessing it expects (PREPROCESSING_ID in its metadata); the API refuses
a model that names a different one.
"""

import re

PREPROCESSING_ID = "sklearn-char-lower-collapse-whitespace-v1"

# scikit-learn's _white_spaces pattern for the char analyzers.
_WHITESPACE_RUNS = re.compile(r"\s\s+")


def preprocess(text: str) -> str:
    """str.lower(), then every run of 2+ whitespace characters becomes one space."""
    return _WHITESPACE_RUNS.sub(" ", text.lower())
