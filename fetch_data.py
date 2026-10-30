"""Download a public SQL injection dataset and merge it with local traffic.

Usage:
    python fetch_data.py                                  # GitHub source (default)
    python fetch_data.py --source kaggle                  # Kaggle source
    python fetch_data.py --source github kaggle           # both, combined
    python fetch_data.py --custom data/feedback/custom_traffic.csv --output data/sqli.csv

Sources:
    github  Morzeux/HttpParamsDataset (MIT). ~19k benign HTTP parameter values
            and ~11k SQLi payloads. Pinned to a commit and verified by SHA-256.
    kaggle  sajid576/sql-injection-dataset (Query/Label CSV, 0/1 labels).
            Needs `pip install kaggle` and API credentials (~/.kaggle/kaggle.json
            or KAGGLE_USERNAME/KAGGLE_KEY).

Rows from the custom traffic file take precedence over public rows with the
same query, so your own labelling always wins.
"""

import argparse
import hashlib
import logging
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import pandas as pd
import requests

from train import LABEL_COLUMN, QUERY_COLUMN, DatasetError, clean_dataset, read_csv_safely

logger = logging.getLogger("sqli.fetch")

MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 30
KAGGLE_TIMEOUT_SECONDS = 600
DEFAULT_KAGGLE_DATASET = "sajid576/sql-injection-dataset"
KAGGLE_SLUG_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class FetchError(RuntimeError):
    """Raised when a dataset cannot be downloaded or verified."""


@dataclass(frozen=True)
class PinnedFile:
    url: str
    sha256: str
    filename: str


# Pinned to an immutable commit so the content (and its hash) never changes.
HTTP_PARAMS_DATASET = PinnedFile(
    url=(
        "https://raw.githubusercontent.com/Morzeux/HttpParamsDataset/"
        "926670a710283f87c05b554680facf3f9530548c/payload_full.csv"
    ),
    sha256="a4e62ba13435ad3dd583c5790db2175629020fc41c56e1b26baa02a9ae45f03d",
    filename="httpparams_payload_full.csv",
)


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_file(source: PinnedFile, dest: Path) -> None:
    """Stream a file to disk, enforcing a size cap and verifying its SHA-256."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = dest.with_name(dest.name + ".part")
    digest = hashlib.sha256()
    received = 0

    logger.info("Downloading %s", source.url)
    try:
        with requests.get(
            source.url,
            stream=True,
            timeout=DOWNLOAD_TIMEOUT_SECONDS,
            headers={"User-Agent": "sqli-detector-fetch/1.0"},
        ) as response:
            response.raise_for_status()
            with tmp_path.open("wb") as handle:
                for chunk in response.iter_content(chunk_size=1 << 16):
                    received += len(chunk)
                    if received > MAX_DOWNLOAD_BYTES:
                        raise FetchError(f"Download exceeded {MAX_DOWNLOAD_BYTES} bytes; aborting")
                    digest.update(chunk)
                    handle.write(chunk)
    except requests.RequestException as exc:
        tmp_path.unlink(missing_ok=True)
        raise FetchError(f"Download failed: {exc}") from exc
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise

    if digest.hexdigest() != source.sha256:
        tmp_path.unlink(missing_ok=True)
        raise FetchError(
            f"SHA-256 mismatch for {source.url}: expected {source.sha256}, got {digest.hexdigest()}"
        )
    os.replace(tmp_path, dest)
    logger.info("Saved %s (%d bytes, checksum verified)", dest, received)


def normalize_http_params(raw: pd.DataFrame) -> pd.DataFrame:
    """Map HttpParamsDataset rows to query/label.

    The dataset also contains XSS, command injection and path traversal
    payloads. They are dropped rather than labelled safe, so the model never
    learns that other attacks are benign.
    """
    missing = {"payload", "attack_type"} - set(raw.columns)
    if missing:
        raise DatasetError(f"Unexpected HttpParamsDataset schema; missing {sorted(missing)}")

    attack_type = raw["attack_type"].str.strip().str.lower()
    keep = attack_type.isin(["norm", "sqli"])
    dropped = attack_type[~keep].value_counts()
    if not dropped.empty:
        logger.info("Dropped non-SQLi attack rows: %s", dropped.to_dict())

    return pd.DataFrame(
        {
            QUERY_COLUMN: raw.loc[keep, "payload"],
            LABEL_COLUMN: (attack_type[keep] == "sqli").astype(int),
        }
    )


def fetch_github(raw_dir: Path, force: bool) -> pd.DataFrame:
    path = raw_dir / HTTP_PARAMS_DATASET.filename
    if force or not path.is_file() or sha256_of(path) != HTTP_PARAMS_DATASET.sha256:
        download_file(HTTP_PARAMS_DATASET, path)
    else:
        logger.info("Using cached %s (checksum verified)", path)
    return normalize_http_params(read_csv_safely(path))


def read_csv_any_encoding(path: Path) -> pd.DataFrame:
    """Kaggle datasets are published as UTF-8 or UTF-16; try both."""
    try:
        return read_csv_safely(path, encoding="utf-8")
    except DatasetError as exc:
        if not isinstance(exc.__cause__, UnicodeError):
            raise
        return read_csv_safely(path, encoding="utf-16")


def fetch_kaggle(dataset: str, raw_dir: Path, force: bool) -> pd.DataFrame:
    if not KAGGLE_SLUG_PATTERN.fullmatch(dataset):
        raise FetchError(f"Invalid Kaggle dataset slug {dataset!r}; expected <owner>/<dataset>")
    # Also look next to the interpreter so an un-activated venv still works.
    search_path = os.pathsep.join([str(Path(sys.executable).parent), os.environ.get("PATH", "")])
    kaggle_cli = shutil.which("kaggle", path=search_path)
    if kaggle_cli is None:
        raise FetchError(
            "Kaggle CLI not found. Run `pip install kaggle` and configure ~/.kaggle/kaggle.json "
            "or the KAGGLE_USERNAME/KAGGLE_KEY environment variables."
        )

    target = raw_dir / "kaggle" / dataset.replace("/", "__")
    target.mkdir(parents=True, exist_ok=True)
    command = [kaggle_cli, "datasets", "download", dataset, "--path", str(target), "--unzip"]
    if force:
        command.append("--force")

    logger.info("Downloading Kaggle dataset %s", dataset)
    try:
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=KAGGLE_TIMEOUT_SECONDS)
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip().splitlines()[-1:] or ["no output"]
        raise FetchError(f"Kaggle download failed (exit {exc.returncode}): {detail[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise FetchError(f"Kaggle download timed out after {KAGGLE_TIMEOUT_SECONDS}s") from exc

    csv_files = sorted(target.rglob("*.csv"))
    if not csv_files:
        raise FetchError(f"No CSV files found in Kaggle dataset {dataset}")
    logger.info("Loading %s", ", ".join(p.name for p in csv_files))
    return pd.concat([read_csv_any_encoding(p) for p in csv_files], ignore_index=True)


def load_custom_traffic(path: Path, encoding: str) -> pd.DataFrame | None:
    if not path.is_file():
        logger.info("No custom traffic file at %s; using the public dataset only", path)
        return None
    custom = clean_dataset(read_csv_safely(path, encoding=encoding))
    logger.info("Loaded %d custom traffic rows from %s", len(custom), path)
    return custom


def merge_sources(public: pd.DataFrame, custom: pd.DataFrame | None) -> pd.DataFrame:
    """Merge public and custom rows; custom labels override public ones."""
    public = clean_dataset(public)
    if custom is None or custom.empty:
        return public

    overridden = int(public[QUERY_COLUMN].isin(custom[QUERY_COLUMN]).sum())
    if overridden:
        logger.info("%d public row(s) overridden by custom traffic", overridden)
    merged = pd.concat([custom, public], ignore_index=True)
    return merged.drop_duplicates(subset=QUERY_COLUMN, keep="first").reset_index(drop=True)


def write_dataset(df: pd.DataFrame, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(path.name + ".tmp")
    df.to_csv(tmp_path, index=False, encoding="utf-8")
    os.replace(tmp_path, path)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch and merge SQLi training data.")
    parser.add_argument(
        "--source",
        nargs="+",
        choices=["github", "kaggle"],
        default=["github"],
        help="One or more public datasets to combine",
    )
    parser.add_argument("--kaggle-dataset", default=DEFAULT_KAGGLE_DATASET, help="<owner>/<dataset>")
    parser.add_argument(
        "--custom",
        type=Path,
        default=Path("data/feedback/custom_traffic.csv"),
        help="Local traffic CSV to merge (also where the ML API's /feedback endpoint appends)",
    )
    parser.add_argument("--custom-encoding", default="utf-8")
    parser.add_argument("--raw-dir", type=Path, default=Path("data/raw"), help="Download cache directory")
    parser.add_argument("--output", type=Path, default=Path("data/sqli.csv"))
    parser.add_argument("--force", action="store_true", help="Re-download even if cached")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    args = parse_args(argv)

    try:
        frames = []
        for source in dict.fromkeys(args.source):
            if source == "github":
                frame = fetch_github(args.raw_dir, args.force)
            else:
                frame = fetch_kaggle(args.kaggle_dataset, args.raw_dir, args.force)
            # Clean per source so differing header spellings ("Query" vs "query") align.
            frames.append(clean_dataset(frame))
        public = pd.concat(frames, ignore_index=True)
        custom = load_custom_traffic(args.custom, args.custom_encoding)
        dataset = merge_sources(public, custom)
        write_dataset(dataset, args.output)
    except (FetchError, DatasetError) as exc:
        logger.error("%s", exc)
        return 1
    except OSError as exc:
        logger.error("File system error: %s", exc)
        return 1

    counts = dataset[LABEL_COLUMN].value_counts()
    logger.info(
        "Wrote %d rows to %s (%d safe, %d sqli)",
        len(dataset),
        args.output,
        counts.get(0, 0),
        counts.get(1, 0),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
