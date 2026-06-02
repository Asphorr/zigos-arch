#!/bin/bash
# Native AML interpreter test harness — runs src/acpi/aml.zig's selfTestExtended()
# under `zig test`, off-target, in sub-seconds (no QEMU boot required).
#
# Why a harness at all: aml.zig can't be `zig test`'d in place — its `../`-relative
# imports (io, mm/paging, debug/debug, driver/pci, acpi/acpi) escape the module
# root. This directory is a stand-in root one level up, with minimal stub modules
# so those imports resolve, plus test.zig asserting selfTestExtended() == 0. The
# SAME selfTestExtended() runs at boot (one PASS/FAIL klog per check), so this is
# the fast half of a two-place proof: extend the interpreter => add a check there
# => it runs here in <1s and again on real firmware at boot.
#
# run.sh copies the REAL aml.zig in on every run, so the harness always tests
# current source (the copy at src/acpi/aml.zig is gitignored).
#
# Usage:  tools/aml-test/run.sh
#         ZIG=/path/to/zig tools/aml-test/run.sh   # override the compiler
cd "$(dirname "$(readlink -f "$0")")"
cp ../../src/acpi/aml.zig src/acpi/aml.zig
ZIG="${ZIG:-zig}"
"$ZIG" test test.zig 2>&1 | tail -40
echo "EXIT=${PIPESTATUS[0]}"
