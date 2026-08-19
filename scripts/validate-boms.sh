#!/usr/bin/env bash
# Validate emitted bills of materials against the PUBLISHED CycloneDX and SPDX
# schemas — not against our own idea of them.
#
# This lives outside the Go module on purpose. Validation needs a JSON-schema
# implementation, and tessera's empty dependency tree is a promise made to every
# program that imports it, so the checker is a CI step rather than a test
# dependency. internal/emit carries no-dependency regression tests that pin the
# specific invariants this script discovered.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

CDX_SCHEMA_URL="https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.6.schema.json"
JSF_SCHEMA_URL="https://raw.githubusercontent.com/CycloneDX/specification/master/schema/jsf-0.82.schema.json"
# CycloneDX references an SPDX licence-id enum by URL. Without it registered
# locally the validator reaches out to the network mid-validation, which fails
# closed on any runner that blocks egress — and only for documents that actually
# carry a resolved licence, so it hides until a rich fixture appears.
SPDXID_SCHEMA_URL="https://raw.githubusercontent.com/CycloneDX/specification/master/schema/spdx.schema.json"
SPDX_SCHEMA_URL="https://spdx.org/schema/3.0.1/spdx-json-schema.json"

echo "==> building tessera"
( cd "$ROOT" && go build -o "$WORK/tessera" ./cmd/tessera )

echo "==> fetching published schemas"
curl -sSL --retry 3 --max-time 60 -o "$WORK/cdx.json"  "$CDX_SCHEMA_URL"
curl -sSL --retry 3 --max-time 60 -o "$WORK/jsf.json"  "$JSF_SCHEMA_URL"
curl -sSL --retry 3 --max-time 60 -o "$WORK/spdx.json"   "$SPDX_SCHEMA_URL"
curl -sSL --retry 3 --max-time 60 -o "$WORK/spdxid.json" "$SPDXID_SCHEMA_URL"

echo "==> generating bills of materials"
mkdir -p "$WORK/boms"
shopt -s nullglob
for model in "$ROOT"/testdata/*.gguf "$ROOT"/testdata/*.onnx "$ROOT"/testdata/*.safetensors; do
  base="$(basename "$model")"
  "$WORK/tessera" bom "$model" --format cyclonedx --reproducible > "$WORK/boms/$base.cdx.json"  2>/dev/null || true
  "$WORK/tessera" bom "$model" --format spdx       --reproducible > "$WORK/boms/$base.spdx.json" 2>/dev/null || true
done

# The golden files are the richest documents this project produces — every
# optional element populated at once — so they are worth validating even though
# no real fixture exercises all of them together.
if [ -d "$ROOT/internal/emit/testdata/golden" ]; then
  echo "==> including emitter golden files"
  for g in "$ROOT"/internal/emit/testdata/golden/*.json; do
    cp "$g" "$WORK/boms/golden-$(basename "$g")"
  done
fi

echo "==> validating"
python3 -m venv "$WORK/venv" >/dev/null
"$WORK/venv/bin/pip" install -q jsonschema
"$WORK/venv/bin/python" - "$WORK" <<'PY'
import json, sys, glob, os
from jsonschema import Draft7Validator, Draft202012Validator, RefResolver

work = sys.argv[1]
cdx  = json.load(open(f"{work}/cdx.json"))
jsf  = json.load(open(f"{work}/jsf.json"))
spdxid = json.load(open(f"{work}/spdxid.json"))
spdx = json.load(open(f"{work}/spdx.json"))

cdx_v  = Draft7Validator(cdx, resolver=RefResolver.from_schema(
            cdx, store={
                "http://cyclonedx.org/schema/jsf-0.82.schema.json": jsf,
                "http://cyclonedx.org/schema/spdx.schema.json": spdxid,
            }))
spdx_v = Draft202012Validator(spdx)

failed = 0
for path in sorted(glob.glob(f"{work}/boms/*.json")):
    name = os.path.basename(path)
    doc  = json.load(open(path))
    v    = spdx_v if name.endswith(".spdx.json") else cdx_v
    errs = sorted(v.iter_errors(doc), key=lambda e: list(e.path))
    if errs:
        failed += 1
        print(f"  FAIL {name} ({len(errs)} error(s))")
        for e in errs[:5]:
            print("       /" + "/".join(map(str, e.path)), "->", e.message[:200])
    else:
        print(f"  PASS {name}")

if failed:
    print(f"\n{failed} document(s) do not conform to the published schemas")
    sys.exit(1)
print("\nall documents conform to the published CycloneDX 1.6 and SPDX 3.0.1 schemas")
PY
