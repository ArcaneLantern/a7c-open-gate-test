"""A7C (ILCE-7C, firmware 2.03) kit 1: read-only service-mode check. Nothing is written to the camera.

Port of the A7 III kit 1 (a7m3_map/camera_tests/K1_readonly/m3_check.py, m3kit1_v1). Same session, same three
commands, same guard. One change: the file-read answers 'missing', 'too large for the camera's service buffer' and
'changed during the read' are named and kept apart from 'differs', so a 17 MB av-cam.bin the camera cannot buffer
is reported as NOT COMPARED instead of NOT MATCHING (status codes from the A7C's libJiritsu.so adj_cmd_get_file2 at
0x5fe8, a7c_map C7-F006).

What it does, in one service session (camera in USB Mass Storage mode):
  1. switches the camera into service mode and logs in with PMCA-RE's public keys (as for the A7 IV / A7 III kits);
  2. READ_HASP (product information);
  3. reads these files, one after another, and compares each with the 2.03 update (size + SHA-256):
       /usr/share/pmbp/DeviceInfo.xml   known answer: if it differs or cannot be read, nothing more is read
       /usr/lib/libJiritsu.so           the library that implements the service file commands
       /usr/lib/libsencore.so           the service-mode library
       /usr/codec/vcd_firmware.bin      the video codec firmware (byte-identical to the A7 III 4.04's)
       /system/av-cam.bin               the imaging/recording program (17 MB)
       /setting/DmmConfig.bin           memory configuration (optional: may be missing)
       /proc/cpuinfo, /proc/iomem       expected empty (optional)
  4. always sends the stop request.

Only three service commands can leave the PC: READ_HASP, SET_FILE_PATH (for the paths above only) and GET_FILE2.
The guards in CT1_usb_first_contact/ct1_common.py refuse anything else before a byte is sent. No setting, file or
memory is written; no settings backup is read (it would carry personal data).

  python -I -B c7_check.py --dry-run                    list exactly what would be sent (simulated camera)
  python -I -B c7_check.py --selftest                   run the checks against the simulated camera
  python -I -B c7_check.py --list                       show which Sony USB devices libusb sees; sends nothing
  python -I -B c7_check.py --go --firmware-shown 2.03   the real run

Results: windows/camera_private/C7K1_<time>_check/ (manifest.json, transcript.jsonl, small files). Large files are
not saved, only their size and SHA-256.
"""
import argparse
import contextlib
import hashlib
import io
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "CT1_usb_first_contact"))
import ct1_common as c                 # noqa: E402  guards, session log, pinned PMCA-RE
import ct1_stage2_service as s2        # noqa: E402  connect(), service_session(), libusb_devices()

KIT = "c7kit1_v1"
TEST = "C7K1"
EXPECTED_MODEL = "ILCE-7C"
EXPECTED_FIRMWARE = "2.03"
EXPECTED = json.loads((HERE / "expected_203.json").read_text(encoding="utf-8"))["files"]
c.PREDICTIONS = HERE / "predictions.json"       # the manifest records this kit's predictions
KEEP_MAX = 1 << 20                              # files up to 1 MB are saved; larger ones are hashed only

# (camera path, required, known answer)
FILES = (
    ("/usr/share/pmbp/DeviceInfo.xml", True, True),
    ("/usr/lib/libJiritsu.so", True, False),
    ("/usr/lib/libsencore.so", True, False),
    ("/usr/codec/vcd_firmware.bin", True, False),
    ("/system/av-cam.bin", True, False),
    ("/setting/DmmConfig.bin", False, False),
    ("/proc/cpuinfo", False, False),
    ("/proc/iomem", False, False),
)

# GET_FILE2 inner status words (A7C libJiritsu.so adj_cmd_get_file2 0x5fe8; the A7 IV's are the same, CT7):
STATUS_NAMES = {
    0: "read",
    0x10000004: "service partition did not mount",
    0x10000006: "missing (stat failed)",
    0x10000015: "too large for the camera's service buffer",
    0x10000008: "could not be opened",
    0x1000000A: "changed during the read",
}


def wire(path):
    """The path as the file commands expect it: relative to /tmp/jiritsu."""
    return b"../.." + path.encode("ascii")


PATHS = tuple(wire(p) for p, _r, _k in FILES)

# The complete list of service packets this kit may send: (packet type, category, code) -> (name, payload test).
# Category 0x1001 codes are the A7C's own (libsencore routing rows, a7c_map C7-F004, identical to the A7 III's and
# the A7 IV's): 0x400F SET_FILE_PATH, 0x4011 GET_FILE2. The write (0x4010), delete (0x4012) and format (0x4003)
# commands are not on the list.
RULES = {
    (c.PFUNC_PRODUCT_INFO, 0x0000, 0x001F): ("READ_HASP", lambda p: p == b"\x00"),
    (c.PFUNC_ADJUST, 0x1001, 0x400F): ("SET_FILE_PATH", lambda p: p[:1] == b"\x00" and p[1:] in PATHS),
    (c.PFUNC_ADJUST, 0x1001, 0x4011): ("GET_FILE2", lambda p: p == b"\x00\xff\x00"),
}


def safe_name(path):
    return path.strip("/").replace("/", "_")


def read_file(camera, path):
    """SET_FILE_PATH then GET_FILE2. Returns (status, payload)."""
    camera._sendAdjustControlPacket(0x1001, 0x400F, b"\x00" + wire(path))
    answer = camera._sendAdjustControlPacket(0x1001, 0x4011, b"\x00\xff\x00")
    status = struct.unpack_from("<I", answer)[0] if len(answer) >= 4 else None
    return status, answer[4:]


def outcome(row, want):
    """match / differs / not compared (camera answered with a non-zero status) / no reference."""
    if row.get("status") not in (0, None):
        return "not compared"
    if want is None:
        return "no reference"
    return "match" if (row["bytes"], row["sha256"]) == (want["bytes"], want["sha256"]) else "differs"


def body(session, camera, expected):
    hasp = camera.readHasp()
    session.save_bytes("hasp.bin", hasp)
    session.results["hasp_bytes"] = len(hasp)
    rows = session.results["files"] = []
    for path, required, known in FILES:
        session.say("Reading %s" % path)
        row = {"path": path, "required": required}
        rows.append(row)
        try:
            status, data = read_file(camera, path)
        except c.GuardRefusal:
            raise
        except Exception as exc:
            row["error"] = "%s: %s" % (type(exc).__name__, exc)
            session.say("  no answer: %s" % row["error"])
            raise c.StopTest("a file read got no answer; stopping (nothing is retried)")
        digest = hashlib.sha256(data).hexdigest()
        row.update(status=status, status_name=STATUS_NAMES.get(status, "unknown status"), bytes=len(data), sha256=digest)
        want = expected.get(path)
        row["outcome"] = outcome(row, want)
        if want:
            row["matches_203"] = row["outcome"] == "match"
        if data and len(data) <= KEEP_MAX:
            session.save_bytes("file_%s.bin" % safe_name(path), data)
        tail = {"match": "  = 2.03", "differs": "  DIFFERS from 2.03", "no reference": "",
                "not compared": "  NOT COMPARED: %s" % row["status_name"]}[row["outcome"]]
        session.say("  status %s, %d bytes, SHA-256 %s%s" % (
            "0x%08x" % status if isinstance(status, int) else status, len(data), digest[:16], tail))
        if known and row["outcome"] == "not compared":
            raise c.StopTest("the known-answer file %s could not be read: status 0x%08x (%s); nothing more is read"
                             % (path, status, row["status_name"]))
        if known and row["outcome"] != "match":
            raise c.StopTest("the known-answer file %s does not match the 2.03 update; nothing more is read" % path)
    required = [r for r in rows if r["required"]]
    differs = [r["path"] for r in required if r["outcome"] == "differs"]
    unread = ["%s (%s)" % (r["path"], r["status_name"]) for r in required if r["outcome"] == "not compared"]
    if differs:
        verdict = "NOT MATCHING: %s" % ", ".join(differs)
        if unread:
            verdict += "; not compared: %s" % ", ".join(unread)
    elif unread:
        verdict = ("2.03 CONFIRMED BY THE FILES THAT COULD BE READ; not compared: %s" % ", ".join(unread))
    else:
        verdict = "2.03 CONFIRMED: every required file equals the 2.03 update"
    session.results["verdict"] = verdict
    session.say("Verdict: " + verdict)


# ------------------------------------------------------------ simulated camera

def stand_in_files():
    """Files for the simulated camera. In the analysis tree the real 2.03 files are used; in the published kit
    (no firmware bytes shipped) stand-ins of the right size are generated and their hashes used as 'expected'."""
    import os
    ext = Path(os.environ.get("C7_EXTRACTED", HERE.parents[1] / "work" / "extracted" / "a7c_203"))
    files, expected = {}, dict(EXPECTED)
    for path, _r, _k in FILES:
        want = EXPECTED.get(path)
        if want is None:
            files[wire(path)] = b""
            continue
        real = ext / want["from_update"]
        if real.is_file():
            files[wire(path)] = real.read_bytes()
        else:
            seed = hashlib.sha256(path.encode()).digest()
            data = (seed * (want["bytes"] // len(seed) + 1))[:want["bytes"]]
            files[wire(path)] = data
            expected[path] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    return files, expected


def sim_driver(files, statuses):
    """The CT1 simulated service device; paths in `statuses` answer that inner status word with no data."""
    import ct1_sim

    class StatusSim(ct1_sim.SimDriver):
        def _handle(self, pfunc, body):
            name_code = struct.unpack_from("<HH", body, 0) if len(body) >= 4 else None
            if name_code == (0x1001, 0x4011) and self._path in statuses:
                c.classify_service_packet(pfunc, body, self.rules)
                return 0, struct.pack("<I", statuses[self._path])
            return super()._handle(pfunc, body)

    return StatusSim("senser", files=files, rules=RULES)


def sim_run(files, expected, statuses=None):
    """One full run against the simulated camera. Returns (session, msc driver, service driver)."""
    import ct1_sim
    c.use_pmca()
    session = c.Session("sim", write=False, test=TEST)
    msc = ct1_sim.SimDriver("msc")
    senser = sim_driver(files, statuses or {})
    with contextlib.redirect_stdout(io.StringIO()):
        s2.phase_a(session, msc)
        try:
            s2.service_session(session, senser, lambda cam: body(session, cam, expected), RULES)
        except c.StopTest as exc:
            session.results["stopped"] = str(exc)
    return session, msc, senser


def dry_run_lines():
    files, expected = stand_in_files()
    session, msc, senser = sim_run(files, expected)
    if msc.unexpected or senser.unexpected:
        raise AssertionError("simulated camera saw something off the list: %r" % (msc.unexpected + senser.unexpected))
    lines, device, auth = [], None, 0

    def flush():
        nonlocal auth
        if auth:
            lines.append("  %d authentication packets of 516 bytes on bulk endpoint 0 "
                         "(PMCA-RE SonySenserAuthDevice.authenticate)" % auth)
            auth = 0

    for e in session.events:
        if e.get("dev") and e["dev"] != device:
            flush()
            device = e["dev"]
            lines.append("To the mass-storage device (after SCSI TEST UNIT READY and INQUIRY):" if device == "msc"
                         else "To the service device:")
        if e["kind"] == "usb_vendor_out":
            flush()
            lines.append("  vendor request out: request %d, value %s, index %s, no data  (%s)"
                         % (e["request"], e["value"], e["index"], e["name"]))
        elif e["kind"] == "usb_out" and e["bytes"] == 516:
            auth += 1
        elif e["kind"] == "service_out":
            flush()
            b = bytes.fromhex(e["hex"])
            lines.append("  service packet type 0x%02x, body %s  (%s%s)" % (
                e["pfunc"], b[:8].hex(" ") + (" ..." if len(b) > 8 else ""), e["name"],
                ": " + b[5:].decode() if e["name"] == "SET_FILE_PATH" else ""))
    flush()
    return lines, session


def selftest():
    failures = []

    def check(name, ok, detail=""):
        print("%-66s %s%s" % (name, "pass" if ok else "FAIL", ("  " + detail) if detail and not ok else ""))
        if not ok:
            failures.append(name)

    files, expected = stand_in_files()
    # 1. normal run
    session, msc, senser = sim_run(files, expected)
    rows = session.results.get("files", [])
    check("normal run reads all %d files" % len(FILES), len(rows) == len(FILES), str(session.results.get("stopped")))
    check("normal run verdict is 2.03 CONFIRMED", session.results.get("verdict", "").startswith("2.03 CONFIRMED:"))
    check("simulated camera saw nothing off the list", not msc.unexpected and not senser.unexpected)
    names = [e["name"] for e in session.events if e["kind"] == "service_out"]
    check("only READ_HASP / SET_FILE_PATH / GET_FILE2 were sent",
          set(names) <= {"READ_HASP", "SET_FILE_PATH", "GET_FILE2"} and names.count("GET_FILE2") == len(FILES))
    vendor = [e["name"] for e in session.events if e["kind"] == "usb_vendor_out"]
    check("stop request sent at the end", vendor[-1:] == ["STOP_SENSER"])
    # 2a. known answer differs -> stop after the first file
    bad = dict(files)
    bad[wire(FILES[0][0])] = b"<not the 2.03 file/>"
    session, _m, _s = sim_run(bad, expected)
    check("known-answer mismatch stops after the first read",
          len(session.results.get("files", [])) == 1 and "known-answer" in session.results.get("stopped", ""))
    vendor = [e["name"] for e in session.events if e["kind"] == "usb_vendor_out"]
    check("  ... and still sends the stop request", vendor[-1:] == ["STOP_SENSER"])
    # 2b. known answer cannot be read -> report the camera status, not a firmware mismatch
    session, _m, _s = sim_run(files, expected, {wire(FILES[0][0]): 0x10000004})
    rows = session.results.get("files", [])
    stopped = session.results.get("stopped", "")
    check("known-answer mount failure is named",
          len(rows) == 1 and rows[0]["status_name"] == "service partition did not mount"
          and rows[0]["outcome"] == "not compared", stopped)
    check("known-answer read failure is not called a mismatch",
          "could not be read" in stopped and "0x10000004" in stopped and "does not match" not in stopped, stopped)
    vendor = [e["name"] for e in session.events if e["kind"] == "usb_vendor_out"]
    check("  ... and still sends the stop request", vendor[-1:] == ["STOP_SENSER"])
    # 3. a required file differs -> all read, verdict NOT MATCHING
    bad = dict(files)
    orig = files[wire("/system/av-cam.bin")]
    bad[wire("/system/av-cam.bin")] = orig[:-1] + bytes([orig[-1] ^ 0xFF])
    session, _m, _s = sim_run(bad, expected)
    check("av-cam difference gives NOT MATCHING", session.results.get("verdict", "").startswith("NOT MATCHING"))
    # 4. av-cam too large for the service buffer -> NOT COMPARED, not NOT MATCHING; run goes on to the end
    session, _m, _s = sim_run(files, expected, {wire("/system/av-cam.bin"): 0x10000015})
    verdict = session.results.get("verdict", "")
    check("av-cam 'too large' gives CONFIRMED BY THE FILES THAT COULD BE READ",
          verdict.startswith("2.03 CONFIRMED BY THE FILES") and "too large" in verdict)
    check("  ... and every file is still asked for", len(session.results.get("files", [])) == len(FILES))
    # 5. 'too large' plus a real difference -> NOT MATCHING names both
    bad = dict(files)
    orig = files[wire("/usr/lib/libsencore.so")]
    bad[wire("/usr/lib/libsencore.so")] = orig[:-1] + bytes([orig[-1] ^ 0xFF])
    session, _m, _s = sim_run(bad, expected, {wire("/system/av-cam.bin"): 0x10000015})
    verdict = session.results.get("verdict", "")
    check("difference plus 'too large': NOT MATCHING, names both",
          verdict.startswith("NOT MATCHING: /usr/lib/libsencore.so") and "not compared: /system/av-cam.bin" in verdict)
    # 6. an optional file missing (camera status 0x10000006) -> run continues, verdict unaffected
    session, _m, _s = sim_run(files, expected, {wire("/setting/DmmConfig.bin"): 0x10000006})
    rows = session.results.get("files", [])
    check("missing optional file: run continues to the end", len(rows) == len(FILES))
    check("  ... recorded as missing, verdict still 2.03 CONFIRMED",
          any(r["path"] == "/setting/DmmConfig.bin" and r["status_name"].startswith("missing") for r in rows)
          and session.results.get("verdict", "").startswith("2.03 CONFIRMED:"))
    # 7. the guard refuses everything else
    for label, pfunc, data in (
            ("file write (0x4010)", c.PFUNC_ADJUST, struct.pack("<HH", 0x1001, 0x4010) + b"\x00\xff\x00ab"),
            ("file delete (0x4012)", c.PFUNC_ADJUST, struct.pack("<HH", 0x1001, 0x4012) + b"\x00\xff"),
            ("format (0x4003)", c.PFUNC_ADJUST, struct.pack("<HH", 0x1001, 0x4003) + b"\x00"),
            ("Jiritsu start (0x4004)", c.PFUNC_ADJUST, struct.pack("<HH", 0x1001, 0x4004) + b"\x00"),
            ("firmware update (0x4006)", c.PFUNC_ADJUST, struct.pack("<HH", 0x1001, 0x4006) + b"\x00"),
            ("backup read (0x603/5)", c.PFUNC_ADJUST, struct.pack("<HH", 0x0603, 0x0005) + b"\x01"),
            ("SET_FILE_PATH to an unlisted path", c.PFUNC_ADJUST, struct.pack("<HH", 0x1001, 0x400F) + b"\x00../../etc/passwd"),
            ("coprocessor debug group 0x60b", c.PFUNC_ADJUST, struct.pack("<HH", 0x060B, 0x0001) + b"\x00"),
            ("memory dump packet type 0xff03", 0xFF03, struct.pack("<HH", 0x0000, 0x0000) + b"\x00")):
        try:
            c.classify_service_packet(pfunc, data, RULES)
            check("guard refuses %s" % label, False, "was allowed")
        except c.GuardRefusal:
            check("guard refuses %s" % label, True)
    # 8. dry-run listing
    lines, _session = dry_run_lines()
    text = "\n".join(lines)
    check("dry run lists only listed paths", all(("SET_FILE_PATH: ../.." + p) in text for p, _r, _k in FILES))
    print("\n%d failed" % len(failures))
    return not failures


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--selftest", action="store_true")
    mode.add_argument("--list", action="store_true")
    mode.add_argument("--go", action="store_true")
    parser.add_argument("--firmware-shown", help="the version the camera's menu shows (must be 2.03)")
    args = parser.parse_args()

    if args.dry_run:
        lines, _session = dry_run_lines()
        print("Kit 1 would send, in this order (simulated camera):")
        print("\n".join(lines))
        return
    if args.selftest:
        sys.exit(0 if selftest() else 1)
    if args.list:
        c.use_pmca()
        session = c.Session("list", write=False, test=TEST)
        c.print_pnp(session, "now")
        try:
            msc, senser = s2.libusb_devices()
        except c.StopTest as exc:
            print(exc)
            return
        print("libusb sees: %d Sony mass-storage device(s) %s, %d Sony service device(s) %s"
              % (len(msc), ["%04x:%04x" % (d.idVendor, d.idProduct) for d in msc],
                 len(senser), ["%04x:%04x" % (d.idVendor, d.idProduct) for d in senser]))
        print("Nothing was sent to any device.")
        return
    if (args.firmware_shown or "").strip() != EXPECTED_FIRMWARE:
        raise SystemExit("This kit is for an %s on firmware %s only. Pass --firmware-shown with the version the "
                         "camera's menu shows (MENU > Setup > Version)." % (EXPECTED_MODEL, EXPECTED_FIRMWARE))
    with c.Session("check", test=TEST) as session:
        session.results.update(kit=KIT, firmware_shown_on_camera=args.firmware_shown)
        inner = s2.connect(session)
        model = (session.results.get("msc_inquiry") or {}).get("model")
        if model is not None:
            session.say("Mass-storage INQUIRY model text: %r" % model)
        try:
            s2.service_session(session, inner, lambda cam: body(session, cam, EXPECTED), RULES)
        finally:
            import time
            time.sleep(3)
            c.print_pnp(session, "after the stop request")
        print("Nothing was written to the camera.")


if __name__ == "__main__":
    main()
