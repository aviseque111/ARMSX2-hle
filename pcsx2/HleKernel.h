// SPDX-License-Identifier: GPL-3.0+
//
// EXPERIMENTAL: high-level emulation (HLE) of the PS2 EE kernel, so that homebrew ELFs can run
// without a BIOS. Milestone M0: boot an ELF and answer a handful of EE syscalls.
//
// The behaviour of the syscalls follows the ones in Play! (Source/ee/PS2OS.cpp, BSD licensed,
// Copyright (c) 2006-2026 Jean-Philip Desjardins). The code here is a fresh implementation.
//
// Off by default. Turn it on by creating an empty file named "hle_kernel.txt" in the data directory
// (the folder that holds "bios" and "sstates"), then boot an .elf file.

#pragma once

#include "common/Pcsx2Defs.h"

namespace HleKernel
{
	/// Re-checks whether HLE kernel mode is requested. Called once per VM boot, from LoadBIOS().
	void Refresh();

	/// Whether HLE kernel mode is on for the current boot.
	bool IsEnabled();

	/// Called at the end of cpuReset(). Loads the boot ELF straight into EE RAM and points the EE
	/// at its entry point, in place of the BIOS boot sequence.
	void OnCpuReset();

	/// Called from the SYSCALL instruction handler in place of raising the exception that
	/// would run the BIOS kernel. Returns true when the call was handled; the EE pc is then
	/// already past the SYSCALL instruction (or deliberately left on it).
	bool HandleSyscall(u8 call);
} // namespace HleKernel
