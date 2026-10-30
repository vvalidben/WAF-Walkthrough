"""Deterministic synthetic training data for the tests and the CI smoke model.

The real datasets (fetch_data.py) are large and not in the repository, so
tests and CI train a small model on generated values instead. It only has to
separate obvious SQLi from obvious benign input; it says nothing about the
production model's accuracy.

    python tests/synthetic_data.py data/sqli.csv     # write a training CSV
"""

import csv
import random
import sys
from pathlib import Path

FIRST_NAMES = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy",
               "mallory", "niaj", "olivia", "peggy", "rupert", "sybil", "trent", "victor", "walter"]
WORDS = ["red", "shoes", "laptop", "garden", "coffee", "table", "summer", "river", "music", "travel",
         "winter", "jacket", "phone", "camera", "kitchen", "book", "lamp", "chair", "bicycle", "pizza"]
CITIES = ["Paris", "Berlin", "Madrid", "Lisbon", "Oslo", "Tunis", "Cairo", "Lima", "Quito", "Osaka"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "curl/8.9.1",
]
TABLES = ["users", "accounts", "admin", "customers", "orders", "members"]
COLUMNS = ["password", "username", "email", "passwd", "card_number", "token"]

ATTACK_TEMPLATES = [
    "{n}' OR '{w}'='{w}",
    "{n}' or {n}={n}--",
    "{n} UNION SELECT {c}, {c2} FROM {t}--",
    "' UNION ALL SELECT NULL,NULL,{c} FROM {t}#",
    "{n}; DROP TABLE {t}--",
    "{n}' AND SLEEP({d})--",
    "{n} AND {n}={n}",
    "{w}'--",
    "{n} AND ASCII(SUBSTRING((SELECT {c} FROM {t} LIMIT 1),{d},1))>{k}",
    "' AND extractvalue(1,concat(0x7e,(SELECT @@version)))--",
    "{n}) OR ({n}={n}",
    "{n} AND (SELECT COUNT(*) FROM {t})>{d}",
    "'; EXEC xp_cmdshell('dir')--",
    "{n} ORDER BY {k}--",
    "-{n} OR 1 GROUP BY CONCAT({c},FLOOR(RAND(0)*2))",
    "{n}' AND (SELECT {d} FROM (SELECT(SLEEP({d})))x)--",
    "admin' AND SUBSTRING({c},1,1)='{l}",
    "{n} WAITFOR DELAY '0:0:{d}'--",
]
BENIGN_TEMPLATES = [
    "{f}", "{f} {f2}", "{f}.{f2}@example.com", "{w} {w2}", "{w} {w2} {w3}", "{n}", "{n}.{d}",
    "2026-{m:02d}-{day:02d}", "{city}", "{n} {w} street", "{w}-{w2}", "+1 555 {n:04d}", "{ua}",
    "I'd like {d} {w}s for my {w2}", "page={d}&sort={w}", "{f}'s {w}", "{w}, {w2} and {w3}",
]


def _vary_case(rng: random.Random, text: str) -> str:
    mode = rng.random()
    if mode < 0.3:
        return text.lower()
    if mode < 0.4:
        return "".join(ch.upper() if rng.random() < 0.5 else ch.lower() for ch in text)
    return text


def generate(seed: int = 7, per_class: int = 400) -> list[tuple[str, int]]:
    """Return unique (query, label) pairs, `per_class` of each label."""
    rng = random.Random(seed)

    def fields() -> dict[str, object]:
        return {
            "n": rng.randint(1, 9999), "d": rng.randint(1, 9), "k": rng.randint(32, 126),
            "w": rng.choice(WORDS), "w2": rng.choice(WORDS), "w3": rng.choice(WORDS),
            "f": rng.choice(FIRST_NAMES), "f2": rng.choice(FIRST_NAMES), "city": rng.choice(CITIES),
            "t": rng.choice(TABLES), "c": rng.choice(COLUMNS), "c2": rng.choice(COLUMNS),
            "l": rng.choice("abcdefxyz"), "m": rng.randint(1, 12), "day": rng.randint(1, 28),
            "ua": rng.choice(USER_AGENTS),
        }

    rows: dict[str, int] = {}
    for label, templates in ((1, ATTACK_TEMPLATES), (0, BENIGN_TEMPLATES)):
        made = 0
        while made < per_class:
            value = rng.choice(templates).format(**fields())
            if label:
                value = _vary_case(rng, value)
            if value not in rows:
                rows[value] = label
                made += 1
    items = list(rows.items())
    rng.shuffle(items)
    return items


def write_csv(path: Path, seed: int = 7, per_class: int = 400) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["query", "label"])
        writer.writerows(generate(seed, per_class))


if __name__ == "__main__":
    write_csv(Path(sys.argv[1] if len(sys.argv) > 1 else "data/sqli.csv"))
