"""text_preprocessing.preprocess() must reproduce scikit-learn's char-analyzer preprocessing exactly.

If it drifts, the ONNX model (which relies on it) scores differently from the
trained pipeline: padding an attack with spaces once lowered its score from
0.98 to 0.58.
"""

import pytest
from sklearn.feature_extraction.text import TfidfVectorizer

from text_preprocessing import preprocess

CASES = [
    "' AND 1  =  1 --",
    "a\t\tb",
    "a \t\n b",
    "single\ttab stays",
    "  leading and trailing  ",
    " nbsp em　ideographic",
    "UNION SeLeCt",
    "ÉCOLE Straße İstanbul",
    "ǅ title case ΑΒΓ",
    "x\x00y",
    "",
]


def _char_ngrams(text: str, low: int, high: int) -> list[str]:
    return [text[i:i + n] for n in range(low, high + 1) for i in range(len(text) - n + 1)]


@pytest.mark.parametrize("text", CASES)
def test_matches_sklearn_char_analyzer(text: str) -> None:
    analyzer = TfidfVectorizer(analyzer="char", ngram_range=(1, 4), lowercase=True).build_analyzer()
    assert analyzer(text) == _char_ngrams(preprocess(text), 1, 4)


def test_lowercases_and_collapses_whitespace_runs() -> None:
    assert preprocess("A  B\t\tC") == "a b c"


def test_keeps_single_whitespace_characters() -> None:
    # scikit-learn only collapses runs of two or more.
    assert preprocess("a\tb\nc") == "a\tb\nc"


def test_is_idempotent() -> None:
    for text in CASES:
        assert preprocess(preprocess(text)) == preprocess(text)
