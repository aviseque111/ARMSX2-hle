// SPDX-License-Identifier: GPL-3.0+
//
// EXPERIMENTAL EE kernel HLE, milestone M0. See HleKernel.h.
//
// What works: loading a plain MIPS ELF into RAM and jumping to it, and these syscalls:
//   SetGsCrt(2) Exit(4) SetupThread(60) SetupHeap(61) EndOfHeap(62)
//   FlushCache(100) iFlushCache(104) GetMemorySize(127)
// Every other syscall is logged once and returns 0.
//
// What does not exist yet: threads and semaphores, interrupt handlers, the IOP side (SIF/RPC),
// GS setup behind SetGsCrt, disc boot. A program that needs any of these will not get far.

#include "HleKernel.h"

#include "Common.h"
#include "Config.h"
#include "Elfheader.h"
#include "Memory.h"
#include "R5900.h"
#include "VMManager.h"

#include "common/Console.h"
#include "common/Error.h"
#include "common/FileSystem.h"
#include "common/Path.h"

#include <cstring>
#include <set>
#include <string>
#include <vector>

namespace HleKernel
{
	static bool s_enabled = false;

	// Kernel state that SetupThread/SetupHeap/EndOfHeap need.
	static u32 s_stack_base = 0; // lowest address of the main thread's stack
	static u32 s_heap_base = 0;
	static bool s_exit_logged = false;
	static std::set<u8> s_unhandled_logged;

	static constexpr u32 kRamSize = Ps2MemSize::MainRam; // 32 MB, what GetMemorySize reports
	static constexpr u32 kStackReserve = 0x2A0; // bytes the kernel keeps at the top of a thread stack
	static constexpr u32 kKernelRamReserve = 0x1000; // the kernel keeps the top 4 KB of RAM

	// MIPS o32 argument registers: a0..a3 are GPR 4..7.
	static inline u32 Arg(int n) { return cpuRegs.GPR.r[4 + n].UL[0]; }

	static inline void SetReturn(u32 value)
	{
		// Syscall results are 32-bit values sign-extended into the 64-bit $v0.
		cpuRegs.GPR.n.v0.UD[0] = static_cast<u64>(static_cast<s64>(static_cast<s32>(value)));
	}

	void Refresh()
	{
		const std::string marker = Path::Combine(EmuFolders::DataRoot, "hle_kernel.txt");
		s_enabled = FileSystem::FileExists(marker.c_str());
		if (s_enabled)
			Console.WriteLn("[HLE] Kernel mode requested by %s (experimental, no BIOS is used).", marker.c_str());
	}

	bool IsEnabled()
	{
		return s_enabled;
	}

	void OnCpuReset()
	{
		s_stack_base = 0;
		s_heap_base = 0;
		s_exit_logged = false;
		s_unhandled_logged.clear();

		if (!s_enabled)
			return;

		const std::string& elf_path = VMManager::Internal::GetELFOverride();
		if (elf_path.empty())
		{
			Console.Warning("[HLE] Nothing to boot: HLE kernel mode can only start an .elf file for now.");
			return;
		}

		ElfObject elf;
		Error error;
		if (!elf.OpenFile(elf_path, false, &error))
		{
			Console.Error("[HLE] Cannot open '%s': %s", elf_path.c_str(), error.GetDescription().c_str());
			return;
		}

		const std::vector<u8>& data = elf.GetData();
		ELF_HEADER header;
		if (data.size() < sizeof(header))
		{
			Console.Error("[HLE] '%s' is too small to be an ELF file.", elf_path.c_str());
			return;
		}
		std::memcpy(&header, data.data(), sizeof(header));

		// 0x7f 'E' 'L' 'F', and machine 8 = MIPS.
		if (std::memcmp(header.e_ident, "\x7f"
		                                "ELF",
				4) != 0 ||
			header.e_machine != 8)
		{
			Console.Error("[HLE] '%s' is not a MIPS ELF file.", elf_path.c_str());
			return;
		}

		u32 loaded_segments = 0;
		for (u32 i = 0; i < header.e_phnum; i++)
		{
			const u64 ph_offset = static_cast<u64>(header.e_phoff) + static_cast<u64>(i) * header.e_phentsize;
			ELF_PHR ph;
			if (ph_offset + sizeof(ph) > data.size())
			{
				Console.Error("[HLE] Program header %u lies outside the file.", i);
				return;
			}
			std::memcpy(&ph, data.data() + ph_offset, sizeof(ph));

			if (ph.p_type != 1 /* PT_LOAD */ || ph.p_memsz == 0)
				continue;

			const u32 dest = ph.p_vaddr & 0x1FFFFFFFu; // strip the kseg0/kseg1 bits
			if (static_cast<u64>(dest) + ph.p_memsz > kRamSize ||
				static_cast<u64>(ph.p_offset) + ph.p_filesz > data.size() ||
				ph.p_filesz > ph.p_memsz)
			{
				Console.Error("[HLE] Segment %u (vaddr %08x, size %08x) does not fit in RAM or in the file.",
					i, ph.p_vaddr, ph.p_memsz);
				return;
			}

			std::memcpy(eeMem->Main + dest, data.data() + ph.p_offset, ph.p_filesz);
			std::memset(eeMem->Main + dest + ph.p_filesz, 0, ph.p_memsz - ph.p_filesz);
			Cpu->Clear(dest, (ph.p_memsz + 3) / 4); // drop any recompiled code for the overwritten range
			loaded_segments++;
		}

		if (loaded_segments == 0)
		{
			Console.Error("[HLE] '%s' has no loadable segments.", elf_path.c_str());
			return;
		}

		cpuRegs.pc = header.e_entry;

		// Note: the normal boot path (EELOAD hook -> ELFLoadingOnCPUThread) is not run here, so the game's
		// CRC, per-game patches and GS fixes are not applied in this mode yet. VMManager turns fast boot off
		// for this mode so that nothing waits for an EELOAD that never runs.
		Console.WriteLn("[HLE] Loaded '%s': %u segment(s), entry point %08x.", elf_path.c_str(), loaded_segments, header.e_entry);
	}

	bool HandleSyscall(u8 call)
	{
		switch (call)
		{
			case 2: // SetGsCrt(interlace, mode, frame/field). Video mode is already set by SYSCALL().
				// TODO(M1): program PMODE/SMODE/DISPLAY registers as the BIOS does.
				Console.WriteLn("[HLE] SetGsCrt(%u, %u, %u): accepted, GS display registers are NOT programmed yet.", Arg(0), Arg(1), Arg(2));
				return true;

			case 4: // Exit
				if (!s_exit_logged)
				{
					Console.WriteLn("[HLE] Exit(): the program has finished. The EE now idles on this instruction.");
					s_exit_logged = true;
				}
				cpuRegs.pc -= 4; // stay on the SYSCALL instruction
				return true;

			case 60: // SetupThread(gp, stack, stack_size, args, root_func) -> initial stack pointer
			{
				const u32 stack_base = Arg(1);
				const u32 stack_size = Arg(2);
				const u32 args_addr = Arg(3);

				// A stack address of -1 means "put it at the top of RAM". The kernel keeps the top 4 KB.
				const u32 stack_top = (stack_base == 0xFFFFFFFFu) ? (kRamSize - kKernelRamReserve) : (stack_base + stack_size);
				s_stack_base = stack_top - stack_size;

				// The C runtime reads argc/argv from the args buffer: tell it there are none.
				if (args_addr != 0 && static_cast<u64>(args_addr & 0x1FFFFFFFu) + 8 <= kRamSize)
					std::memset(eeMem->Main + (args_addr & 0x1FFFFFFFu), 0, 8);

				const u32 sp = stack_top - kStackReserve;
				SetReturn(sp);
				Console.WriteLn("[HLE] SetupThread(stack=%08x, size=%08x, args=%08x) -> sp=%08x", stack_base, stack_size, args_addr, sp);
				return true;
			}

			case 61: // SetupHeap(heap_base, heap_size) -> end of heap
			{
				const u32 heap_base = Arg(0);
				const u32 heap_size = Arg(1);
				s_heap_base = (heap_size == 0xFFFFFFFFu) ? s_stack_base : (heap_base + heap_size);
				SetReturn(s_heap_base);
				Console.WriteLn("[HLE] SetupHeap(base=%08x, size=%08x) -> %08x", heap_base, heap_size, s_heap_base);
				return true;
			}

			case 62: // EndOfHeap
				SetReturn(s_heap_base);
				Console.WriteLn("[HLE] EndOfHeap() -> %08x", s_heap_base);
				return true;

			case 100: // FlushCache
			case 104: // iFlushCache
				// The EE caches are not modelled, so there is nothing to flush.
				SetReturn(0);
				return true;

			case 127: // GetMemorySize
				SetReturn(kRamSize);
				Console.WriteLn("[HLE] GetMemorySize() -> %08x", kRamSize);
				return true;

			default:
				if (s_unhandled_logged.insert(call).second)
				{
					Console.Warning("[HLE] Unimplemented syscall %u (%s), returning 0. This message is shown once per call.",
						call, R5900::bios[call]);
				}
				SetReturn(0);
				return true;
		}
	}
} // namespace HleKernel
