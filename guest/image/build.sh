#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
GUEST_DIR="${REPO_ROOT}/guest"
IMAGE_DIR="${GUEST_DIR}/image"

ALPINE_VERSION=${ALPINE_VERSION:-3.20.3}
ALPINE_BRANCH=${ALPINE_BRANCH:-v3.20}
ARCH=${ARCH:-$(uname -m)}
if [[ "${ARCH}" == "x86_64" && "$(uname -s)" == "Darwin" ]]; then
    if sysctl -n hw.optional.arm64 >/dev/null 2>&1; then
        if [[ "$(sysctl -n hw.optional.arm64)" == "1" ]]; then
            ARCH="aarch64"
        fi
    fi
fi
if [[ "${ARCH}" == "arm64" ]]; then
    ARCH="aarch64"
fi

OUT_DIR=${OUT_DIR:-"${IMAGE_DIR}/out"}
ROOTFS_DIR="${OUT_DIR}/rootfs"
INITRAMFS="${OUT_DIR}/initramfs.cpio.gz"
CACHE_DIR="${IMAGE_DIR}/.cache"

SANDBOXD_BIN=${SANDBOXD_BIN:-"${GUEST_DIR}/zig-out/bin/sandboxd"}
SANDBOXFS_BIN=${SANDBOXFS_BIN:-"${GUEST_DIR}/zig-out/bin/sandboxfs"}

ALPINE_TARBALL="alpine-minirootfs-${ALPINE_VERSION}-${ARCH}.tar.gz"
ALPINE_URL=${ALPINE_URL:-"https://dl-cdn.alpinelinux.org/alpine/${ALPINE_BRANCH}/releases/${ARCH}/${ALPINE_TARBALL}"}
EXTRA_PACKAGES=${EXTRA_PACKAGES:-python3 linux-virt rng-tools bash ca-certificates}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required command: $1" >&2
        exit 1
    fi
}

require_cmd tar
require_cmd cpio
require_cmd gzip
require_cmd curl
require_cmd python3

mkdir -p "${CACHE_DIR}" "${OUT_DIR}"

if [[ ! -f "${SANDBOXD_BIN}" || ! -f "${SANDBOXFS_BIN}" ]]; then
    echo "guest binaries not found, building..." >&2
    (cd "${GUEST_DIR}" && ${ZIG:-zig} build -Doptimize=ReleaseSmall)
fi

if [[ ! -f "${CACHE_DIR}/${ALPINE_TARBALL}" ]]; then
    echo "downloading ${ALPINE_URL}" >&2
    curl -L "${ALPINE_URL}" -o "${CACHE_DIR}/${ALPINE_TARBALL}"
fi

rm -rf "${ROOTFS_DIR}"
mkdir -p "${ROOTFS_DIR}"

tar -xzf "${CACHE_DIR}/${ALPINE_TARBALL}" -C "${ROOTFS_DIR}"

if [[ -n "${EXTRA_PACKAGES}" ]]; then
    ROOTFS_DIR="${ROOTFS_DIR}" CACHE_DIR="${CACHE_DIR}" ARCH="${ARCH}" EXTRA_PACKAGES="${EXTRA_PACKAGES}" python3 - <<'PY'
import os
import re
import sys
import tarfile
import subprocess

rootfs_dir = os.environ["ROOTFS_DIR"]
cache_dir = os.environ["CACHE_DIR"]
arch = os.environ["ARCH"]
packages = [p for p in os.environ.get("EXTRA_PACKAGES", "").split() if p]

if not packages:
    sys.exit(0)

repos_file = os.path.join(rootfs_dir, "etc", "apk", "repositories")
with open(repos_file, "r", encoding="utf-8") as handle:
    repos = [line.strip() for line in handle if line.strip() and not line.startswith("#")]

pkg_meta = {}
pkg_repo = {}
provides = {}

def download(url: str, path: str) -> None:
    subprocess.check_call(["curl", "-L", "-o", path, url])


def safe_name(repo: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", repo)

def parse_index(index_path: str, repo: str) -> None:
    current = {}
    def commit(entry):
        name = entry.get("P")
        if not name or name in pkg_meta:
            return
        pkg_meta[name] = entry
        pkg_repo[name] = repo
        for token in entry.get("p", "").split():
            provide = token.split("=", 1)[0]
            provides.setdefault(provide, name)

    with open(index_path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.rstrip("\n")
            if not line:
                if current:
                    commit(current)
                    current = {}
                continue
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            current[key] = value
        if current:
            commit(current)

for repo in repos:
    safe = safe_name(repo)
    index_path = os.path.join(cache_dir, f"APKINDEX-{safe}-{arch}")
    if not os.path.exists(index_path):
        tar_path = index_path + ".tar.gz"
        url = f"{repo}/{arch}/APKINDEX.tar.gz"
        download(url, tar_path)
        with tarfile.open(tar_path, "r:gz") as tar:
            tar.extract("APKINDEX", cache_dir, filter="fully_trusted")
        os.replace(os.path.join(cache_dir, "APKINDEX"), index_path)
    parse_index(index_path, repo)


def normalize_dep(dep: str) -> str:
    dep = dep.lstrip("!")
    dep = re.split(r"[<>=~]", dep, maxsplit=1)[0]
    return dep


def resolve_pkg(dep: str):
    if dep in pkg_meta:
        return dep
    return provides.get(dep)


needed = []
seen = set()
queue = list(packages)

while queue:
    dep = normalize_dep(queue.pop(0))
    if not dep:
        continue
    pkg_name = resolve_pkg(dep)
    if not pkg_name:
        print(f"warning: unable to resolve {dep}", file=sys.stderr)
        continue
    if pkg_name in seen:
        continue
    seen.add(pkg_name)
    needed.append(pkg_name)
    deps = pkg_meta[pkg_name].get("D", "")
    for token in deps.split():
        queue.append(token)

for pkg_name in needed:
    meta = pkg_meta[pkg_name]
    repo = pkg_repo[pkg_name]
    version = meta["V"]
    apk_name = f"{pkg_name}-{version}.apk"
    apk_path = os.path.join(cache_dir, f"{arch}-{apk_name}")
    if not os.path.exists(apk_path):
        url = f"{repo}/{arch}/{apk_name}"
        download(url, apk_path)
    with tarfile.open(apk_path, "r:gz") as tar:
        tar.extractall(rootfs_dir, filter="fully_trusted")
PY
fi

install -m 0755 "${SANDBOXD_BIN}" "${ROOTFS_DIR}/usr/bin/sandboxd"
install -m 0755 "${SANDBOXFS_BIN}" "${ROOTFS_DIR}/usr/bin/sandboxfs"
install -m 0755 "${IMAGE_DIR}/init" "${ROOTFS_DIR}/init"

if [[ -n "${MITM_CA_CERT:-}" && -f "${MITM_CA_CERT}" ]]; then
    install -d "${ROOTFS_DIR}/usr/local/share/ca-certificates"
    install -m 0644 "${MITM_CA_CERT}" "${ROOTFS_DIR}/usr/local/share/ca-certificates/gondolin-mitm-ca.crt"

    if [[ -f "${ROOTFS_DIR}/etc/ssl/certs/ca-certificates.crt" ]]; then
        cat "${MITM_CA_CERT}" >> "${ROOTFS_DIR}/etc/ssl/certs/ca-certificates.crt"
    fi
fi

mkdir -p "${ROOTFS_DIR}/proc" "${ROOTFS_DIR}/sys" "${ROOTFS_DIR}/dev" "${ROOTFS_DIR}/run"

(
    cd "${ROOTFS_DIR}"
    find . -print0 | cpio --null -ov --format=newc | gzip -9 > "${INITRAMFS}"
)

echo "initramfs written to ${INITRAMFS}"
