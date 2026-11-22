"""Download the public datasets the evaluation uses and check their hashes.

    python evaluation/fetch_data.py

Splunk attack_data (Apache-2.0): 56 CloudTrail samples, about 57 MB.
flaws.cloud logs (summitroute.com): 1.9 million events, 252 MB download.
Both land in evaluation/data/, which git ignores. Nothing downloaded is run.
"""
import hashlib
import io
import sys
import tarfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).parent
DATA = HERE / "data"
SPLUNK_URL = "https://media.githubusercontent.com/media/splunk/attack_data/master/"
FLAWS_URL = "https://summitroute.com/downloads/flaws_cloudtrail_logs.tar"


def local_name(repo_path):
    name = repo_path.removeprefix("datasets/attack_techniques/").removeprefix("datasets/")
    return name.replace("/", "__")


def download(url):
    with urllib.request.urlopen(url, timeout=120) as response:
        return response.read()


def fetch_splunk():
    target = DATA / "splunk"
    target.mkdir(parents=True, exist_ok=True)
    for repo_path in (HERE / "splunk_paths.txt").read_text().split():
        path = target / local_name(repo_path)
        if not path.exists():
            print(f"splunk: {path.name}")
            path.write_bytes(download(SPLUNK_URL + repo_path))


def fetch_flaws():
    target = DATA / "flaws"
    if (target / "flaws_cloudtrail_logs").exists():
        return
    print("flaws: downloading 252 MB")
    archive = tarfile.open(fileobj=io.BytesIO(download(FLAWS_URL)))
    target.mkdir(parents=True, exist_ok=True)
    for member in archive.getmembers():
        name = Path(member.name)
        if member.isfile() and name.parent.name == "flaws_cloudtrail_logs" \
                and name.name.endswith(".json.gz"):
            out = target / "flaws_cloudtrail_logs" / name.name
            out.parent.mkdir(exist_ok=True)
            out.write_bytes(archive.extractfile(member).read())


def verify():
    bad = 0
    for line in (HERE / "checksums.sha256").read_text().splitlines():
        expected, name = line.split(maxsplit=1)
        path = DATA / name.lstrip("*")
        actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else "missing"
        if actual != expected:
            print(f"checksum mismatch: {name} ({actual})")
            bad += 1
    return bad


def main():
    fetch_splunk()
    fetch_flaws()
    bad = verify()
    print("all checksums match" if not bad else f"{bad} files differ from the evaluation")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
