# A7C test kit 1: read-only check (firmware 2.03)

This is the first camera step for the Sony A7C (ILCE-7C) on firmware 2.03. It is the A7 III kit 1 adapted to the A7C. The goals are the same as for the A7 III: open gate (full-height 3:2 video), the video encoder, and 10-bit recording.

**This kit only reads. It changes nothing in the camera: no setting, no file, no memory.**

It answers four questions before anything else is built for this camera:

1. Does the A7C accept the USB service-mode login used by the A7 IV, A7S III and A7 III kits?
2. Do its file-read commands answer?
3. Is the camera's software byte for byte the 2.03 update the study was made from?
4. Which memory configuration file is installed?

Everything later (memory reads, then any patch) depends on these answers.

## What it does

One USB session with the camera in Mass Storage mode:

1. It switches the camera to service mode and logs in. This uses the public procedure from Sony-PMCA-RE, the same as the A7 IV, A7S III and A7 III kits.
2. It reads the product information (`READ_HASP`).
3. It reads these files and compares each with the 2.03 update (size and SHA-256 checksum):

   | File | Why |
   |---|---|
   | `/usr/share/pmbp/DeviceInfo.xml` | known answer: if it differs, nothing more is read |
   | `/usr/lib/libJiritsu.so`, `/usr/lib/libsencore.so` | the service-mode libraries |
   | `/usr/codec/vcd_firmware.bin` | the video codec's firmware |
   | `/system/av-cam.bin` (17 MB) | the imaging and recording program |
   | `/setting/DmmConfig.bin` | memory configuration; may be missing |
   | `/proc/cpuinfo`, `/proc/iomem` | expected to come back empty |

4. It always ends with the stop request. The camera then leaves service mode; switch it off and on if it does not return to normal.

Only three service commands can be sent: `READ_HASP`, `SET_FILE_PATH` (for the paths above only) and `GET_FILE2`. The script refuses anything else before a byte leaves the PC: write, delete, format, settings commands, memory commands. `selftest.cmd` shows this.

The settings backup is **not** read, because it would carry personal data. Large files are not saved, only their size and checksum.

The camera may answer that a file is too large for its service buffer. This is most likely for `av-cam.bin`. The kit then marks that file **not compared**, not "different". The run goes on, and the verdict names the file.

## Before you start

1. The camera's menu must show **Ver. 2.03** (MENU → Setup → Version). On any other version, stop and tell us the version.
2. **USB Connection Mode: Mass Storage** (MENU → Setup → USB Connection). Note your current setting so you can put it back.
3. A charged battery and a memory card in the camera.
4. Unplug other Sony USB devices from the PC.

## Windows, once

1. Install Python 3.10 or later from python.org, with the "py launcher".
2. Run `windows/setup.cmd`.
3. Run `windows/selftest.cmd`. It needs no camera and must end with `0 failed`. It also prints every packet the real run would send.
4. Install the libusb-win32 driver for the camera with [Zadig](https://zadig.akeo.ie):
   - Connect the camera (Mass Storage), then in Zadig: Options → List All Devices, pick the camera, choose libusb-win32, Replace Driver.
   - The first run switches the camera to service mode, where it shows up as a new device, probably `054C:0336`. It does not stay there long enough to do this by hand. So beforehand, in Zadig: Device → Create New Device, any name, USB ID `054C` `0336`, libusb-win32, Install Driver.
   - `windows/list_devices.cmd` shows what Windows and libusb see. It sends nothing.

macOS is not supported by this kit yet.

## The run

1. Camera on, Mass Storage mode, connected.
2. Run `windows/check_readonly.cmd` and type the version the camera's menu shows (`2.03`).
3. On a first run it may stop with "EXPECTED on a first run: … no libusb driver yet". Leave the camera on and connected, do the Zadig step for the service device, and run again.
4. The end of the output shows the verdict:
   - `2.03 CONFIRMED`;
   - `2.03 CONFIRMED BY THE FILES THAT COULD BE READ; not compared: <file> (<reason>)`;
   - or `NOT MATCHING: <files>`.

## What the result tells us

| Result | Meaning for the A7C work |
|---|---|
| Stops before "Authenticating", or the login fails | The service route used by every other kit does not work on this body. Nothing more can be built until another way in is found. |
| Login passes, but `DeviceInfo.xml` does not answer or differs | The login works but the file commands do not. Later steps that load a helper the way the A7 IV kits do cannot work yet. |
| `2.03 CONFIRMED` | The camera runs exactly the software that was analysed. Addresses and patches worked out from the 2.03 update apply to it. |
| `2.03 CONFIRMED BY THE FILES THAT COULD BE READ` | Almost the same, with one gap: `av-cam.bin` was too large for the camera's service buffer, so its version rests on the other files only. That is weaker evidence. A later memory read can check `av-cam.bin` directly. |
| `NOT MATCHING` | The camera's software differs from the 2.03 update. Nothing that depends on addresses is built until we know which version it runs. |
| `DmmConfig.bin` missing or different | Not a fault. It shows which memory layout this camera uses, which matters for the later steps' buffer sizes. |

## Please send back

The newest folder in `windows/camera_private` (zip it), and one line on what the camera's screen showed during and after the run. The folder holds:
- `transcript.jsonl` (everything printed and every USB exchange);
- `manifest.json` (results);
- the small files read.

Serial numbers are masked in the device listings.

## What is known so far (static analysis of the 2.03 update)

- The A7C update decrypts with the public CXD90045 key, the same key as the A7 III's. It is the same chip generation as the A7 III (model id `0x91030019`; the A7 III is `0x71030014`). The partition layout (`mount.conf`) is identical to the A7 III's.
- The A7C's service library holds the same three login key blocks as the A7 IV's and the A7 III's. All 17 file-command codes (`JIRITSU_*`) are the same as on both cameras.
- Its file-read command works like the A7 IV's: it sizes a file with `stat`, takes a buffer of that size from the camera's memory manager, and gives distinct answers for "missing", "too large" and "changed during the read".
- Its video codec firmware (`vcd_firmware.bin`) is **byte for byte the A7 III 4.04's**. So the A7 III's codec findings hold for the A7C: the codec firmware has a complete 10-bit path, and it does not check picture width or height.
- Its imaging program (`av-cam.bin`) is a different build from the A7 III's, but it has the same load address and the same IMX410 sensor driver.

None of this has been tried on a camera. This kit is the first contact.

## Licence and third-party code

`windows/tools/third_party/sony-pmca-re` holds the unmodified USB transport files of [Sony-PMCA-RE](https://github.com/ma1co/Sony-PMCA-RE), pinned by checksum (`PINNED.json`). The `CT1_usb_first_contact` scripts are the A7 IV / A7S III kits' guarded USB layer, copied unchanged (`PROVENANCE.json`). No Sony firmware is included, only sizes and checksums.
