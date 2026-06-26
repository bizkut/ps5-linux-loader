# PS5 Linux Loader - Agent Guide

## Git Commit Rules
- Do NOT include AI notations in commit messages (no "Generated with Devin", "Co-Authored-By: Devin", etc.)
- Write commit messages as a normal developer would — concise, focused on why

## Overview
The PS5 Linux loader is a payload ELF that runs on the PS5 OS before booting Linux.
It defeats the hypervisor, initializes hardware, copies the kernel/initrd into memory, and boots Linux.

## Build
Uses the `bizkut/ps5-payload-sdk:python3.12-ci` docker image:
```bash
docker run --rm -v $(pwd):/work -w /work bizkut/ps5-payload-sdk:python3.12-ci \
  bash -c "apt-get update -qq && apt-get install -y -qq xxd && make clean all"
```
Output: `bin/ps5-linux-loader.elf`

## Key Files
- `source/main.c` — entry point, orchestrates the boot sequence
- `source/loader.c` — kernel/initrd loading logic
- `shellcode_kernel/boot_linux.c` — kernel-mode shellcode that runs before Linux starts
  - Initializes display back-ends via MP3 commands
  - `mp3_set_hdcp_packet(be, 1)` — cmd 21 (HDCP packet setup)
  - `mp3_enable_output(be, 1)` — cmd 22 (enable display output)
  - be=0: HDMI, be=1: USB-C
- `shellcode_hv/boot_linux.c` — hypervisor-level shellcode (VRAM config, e820 map)
- `shellcode_kernel/hv_defeat_0304.c` / `hv_defeat_0506.c` — HV defeat for different FW versions

## Deployment
- The ELF must be loaded as a payload on the PS5 OS (via exploit/JB)
- It runs BEFORE Linux boots — it is NOT copied to the running Linux system
- The loader initializes hardware (including display) then boots the kernel

## MP3 Commands
MP3 commands are sent to the PSP (Platform Security Processor) Trusted Application:
- cmd 21 (`mp3_set_hdcp_packet`): Sets HDCP packet for a display back-end
- cmd 22 (`mp3_enable_output`): Enables display output for a back-end
- be=0: HDMI back-end, be=1: USB-C back-end
- Both HDMI and USB-C are now initialized in the loader

## USB-C DP Alt Mode
The loader initializes USB-C display via `mp3_enable_output(1, 1)` but this does NOT
configure the combo PHY registers directly. PHY configuration is done in the Linux
kernel driver (`dcn201_link_encoder_acquire_phy` in the amdgpu driver).

See `ps5-linux-patches/USB-C-DP-ALT-MODE.md` for full details.
