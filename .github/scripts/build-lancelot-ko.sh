#!/usr/bin/env bash
# Build dfroot.ko for a non-GKI device: Xiaomi Redmi 9 (lancelot, MTK MT6769,
# kernel 4.14). Stock lancelot kernel sources were never released by Xiaomi
# (MiCode#1303 open since 2020), so the kernel tree below is the closest public
# reconstruction. If a device test fails with an insmod rejection, swap the
# KERNEL_* values and rebuild:
#   - Jbub5/android_kernel_xiaomi_mt6768 @ kernel-tree (lineage-23.0 base)
#   - ramabondanp/kernel_xiaomi_mt6768 @ genom-release (MTK bsp k39tv1_64_*)
#   - techyminati/minati_kernel_lancelin @ stock-upstream
#
# All inputs can be overridden via env vars; toolchain is a pinned AOSP
# kernel-build clang prebuilt.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

KERNEL_REPO="${KERNEL_REPO:-Jbub5/android_kernel_xiaomi_mt6768}"
KERNEL_BRANCH="${KERNEL_BRANCH:-kernel-tree}"
KERNEL_REF="${KERNEL_REF:-b87145cdf9c33d2404c551b03f235d647bc7c1db}"
KERNEL_CONFIG="${KERNEL_CONFIG:-lancelot_defconfig}"

# AOSP kernel-build prebuilt: clang-r487747c == clang 17 (Android U).
CLANG_URL="${CLANG_URL:-https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86/+archive/refs/heads/main-kernel-build-2023/clang-r487747c.tar.gz}"

KO_OUT_NAME="${KO_OUT_NAME:-dfroot-android11-4.14.ko}"

OUT="${ROOT}/kernel"
BLD="${OUT}/out"
SRCDIR_ROOT="${ROOT}/toolchain"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1"; exit 1; }; }
for c in git curl tar make; do need "$c"; done

echo "=== toolchain: $(basename "$CLANG_URL") ==="
mkdir -p "$SRCDIR_ROOT"
if [ ! -x "$SRCDIR_ROOT/bin/clang" ]; then
    curl -fsSL "$CLANG_URL" -o /tmp/clang.tar.gz
    rm -rf "$SRCDIR_ROOT"/*
    tar -xzf /tmp/clang.tar.gz -C "$SRCDIR_ROOT"
fi
export PATH="$SRCDIR_ROOT/bin:$PATH"
clang --version | head -1

echo "=== kernel source: ${KERNEL_REPO}@${KERNEL_REF} ==="
if [ ! -d "$OUT/.git" ]; then
    git clone --depth 1 --branch "$KERNEL_BRANCH" "https://github.com/${KERNEL_REPO}" "$OUT"
fi
cd "$OUT"
if [ "$(git rev-parse HEAD)" != "$KERNEL_REF" ]; then
    git fetch origin "$KERNEL_REF" --depth 1
    git checkout --detach "$KERNEL_REF"
fi
echo "head: $(git rev-parse HEAD) ($(git log --oneline -1))"

kvers() { awk '/^(VERSION|PATCHLEVEL|SUBLEVEL) /{print $3}' Makefile | paste -sd. -; }
KVERS="$(kvers)"
echo "kernel: ${KVERS}"
case "$KVERS" in 4\.14*) ;; *) echo "FATAL: expected a 4.14 kernel tree, got ${KVERS}"; exit 1;; esac

MAKE_BASE="O=${BLD} ARCH=arm64 CC=clang CROSS_COMPILE=aarch64-linux-gnu-"

echo "=== config: ${KERNEL_CONFIG} ==="
if [ ! -e "${BLD}/.config" ]; then
    make ${MAKE_BASE} "$KERNEL_CONFIG"
else
    echo "reusing cached config"
fi

# The module needs kprobes/kallsyms/modules present in the kernel it is
# linked against. These must ALSO be enabled in the device's STOCK kernel
# build, or the running kernel will reject the module at insmod time
# ("invalid module format" / "Unknown symbol"). Verify on device against
# /proc/config.gz and adjust KERNEL_CONFIG if needed.
./scripts/config --file "${BLD}/.config" \
    --enable MODULES --enable MODULE_UNLOAD \
    --enable KPROBES --enable KALLSYMS --enable KALLSYMS_ALL
make ${MAKE_BASE} olddefconfig
for cfg in MODULES KPROBES KALLSYMS KALLSYMS_ALL; do
    grep -q "^CONFIG_${cfg}=y" "${BLD}/.config" \
        || { echo "FATAL: CONFIG_${cfg} not enabled"; exit 1; }
done
if grep -q "^CONFIG_MODVERSIONS=y" "${BLD}/.config"; then
    echo "WARN: CONFIG_MODVERSIONS=y — symbol CRCs must match the stock kernel"
    echo "=== building in-tree modules (generates Module.symvers) ==="
    make ${MAKE_BASE} -j"$(nproc)" modules
else
    echo "=== preparing kernel build tree ==="
    make ${MAKE_BASE} prepare
    make ${MAKE_BASE} scripts
fi

# Runtime rewrites the ko vermagic to the device release (exp.c), so a
# mismatch here is tolerated, but print it for diagnostics.
echo "=== dfroot.ko ==="
make -C "$ROOT/lkm" KDIR="$OUT" \
    EXTRA_MAKE_ARGS="${MAKE_BASE} -j$(nproc)" \
    OBJCOPY="aarch64-linux-gnu-objcopy"

mkdir -p "$ROOT/out"
cp lkm/dfroot.ko "$ROOT/out/${KO_OUT_NAME}"

echo "=== verify ==="
aarch64-linux-gnu-objdump -f "$ROOT/out/${KO_OUT_NAME}" | grep -E 'file format|architecture'
vermagic="$(modinfo -F vermagic "$ROOT/out/${KO_OUT_NAME}" || true)"
if [ -z "$vermagic" ]; then
    echo "FATAL: no vermagic in .modinfo"
    exit 1
fi
echo "built vermagic: $vermagic"
ls -l "$ROOT/out"
echo "OK: $ROOT/out/${KO_OUT_NAME}"
