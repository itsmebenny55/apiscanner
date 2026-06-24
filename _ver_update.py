import re, pathlib

BASE = pathlib.Path("i:/apiscanner")
TODAY = "26-04-2026"
NEW_VER_PY = "4.0"
NEW_VER_FULL = "4.0.0"

py_files = [
    "ai_client.py", "safe_consumption_audit.py", "apiscan.py",
    "broken_auth_audit.py", "auth_utils.py", "bola_audit.py",
    "business_flow_audit.py", "broken_object_property_audit.py",
    "authorization_audit.py", "build_review.py", "doc_generator.py",
    "inventory_audit.py", "misconfiguration_audit.py", "openapi_universal.py",
    "report_utils.py", "resource_consumption_audit.py", "ssrf_audit.py",
    "swagger_generator.py", "swagger_utils.py", "swagger_universal_tool.py",
    "version.py",
]

for fname in py_files:
    p = BASE / fname
    if not p.exists():
        print(f"SKIP (not found): {fname}")
        continue
    original = p.read_text(encoding="utf-8")
    updated = re.sub(
        r"# version \S.*?(?=#\s*$)",
        f"# version {NEW_VER_PY} {TODAY}                              ",
        original,
        flags=re.MULTILINE
    )
    if fname == "version.py":
        updated = re.sub(r'__version__\s*=\s*"[^"]+"', f'__version__ = "{NEW_VER_FULL}"', updated)
    if updated != original:
        p.write_text(updated, encoding="utf-8")
        print(f"UPDATED: {fname}")
    else:
        print(f"NO CHANGE: {fname}")

html_file = BASE / "index.html"
html = html_file.read_text(encoding="utf-8")
html_new = html.replace("v3.2.1", "v4.0").replace("3.2.1", "4.0")
if html_new != html:
    html_file.write_text(html_new, encoding="utf-8")
    print("UPDATED: index.html")
else:
    print("NO CHANGE: index.html")

print("Done.")
