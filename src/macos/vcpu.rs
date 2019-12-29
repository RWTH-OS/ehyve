use consts::*;
use error::*;
use xhypervisor;
use xhypervisor::consts::vmcs::*;
use xhypervisor::consts::vmx_cap::{PIN_BASED_INTR,PIN_BASED_NMI,PIN_BASED_VIRTUAL_NMI,
	CPU_BASED_SECONDARY_CTLS,CPU_BASED_MWAIT,CPU_BASED_MONITOR,CPU_BASED_TSC_OFFSET,
	CPU_BASED_TPR_SHADOW,VMENTRY_LOAD_EFER,VMENTRY_GUEST_IA32E};
use xhypervisor::consts::vmx_exit;
use xhypervisor::{read_vmx_cap, vCPU, x86Reg};
use std;
use vm::VirtualCPU;
use x86::controlregs::*;
use x86::msr::*;
use x86::segmentation::*;
use x86::Ring;

/* desired control word constrained by hardware/hypervisor capabilities */
fn cap2ctrl(cap: u64, ctrl: u64) -> u64 {
	(ctrl | (cap & 0xffffffff)) & (cap >> 32)
}

lazy_static! {
	static ref CAP_PINBASED: u64 = {
		let cap: u64 = { read_vmx_cap(&xhypervisor::VMXCap::PINBASED).unwrap() };
		cap2ctrl(cap, PIN_BASED_INTR|PIN_BASED_NMI|PIN_BASED_VIRTUAL_NMI)
	};

	static ref CAP_PROCBASED: u64 = {
		let cap: u64 = { read_vmx_cap(&xhypervisor::VMXCap::PROCBASED).unwrap() };
		cap2ctrl(cap, CPU_BASED_SECONDARY_CTLS|CPU_BASED_MWAIT|CPU_BASED_MONITOR|
			CPU_BASED_TSC_OFFSET|CPU_BASED_TPR_SHADOW)
	};

	static ref CAP_PROCBASED2: u64 = {
		let cap: u64 = { read_vmx_cap(&xhypervisor::VMXCap::PROCBASED2).unwrap() };
		cap2ctrl(cap, 0)
	};

	static ref CAP_ENTRY: u64 = {
		let cap: u64 = { read_vmx_cap(&xhypervisor::VMXCap::ENTRY).unwrap() };
		cap2ctrl(cap, VMENTRY_LOAD_EFER|VMENTRY_GUEST_IA32E)
	};

	static ref CAP_EXIT: u64 = {
		let cap: u64 = { read_vmx_cap(&xhypervisor::VMXCap::EXIT).unwrap() };
		cap2ctrl(cap, 0)
	};
}

pub struct EhyveCPU {
	id: u32,
	vcpu: vCPU,
}

impl EhyveCPU {
	pub fn new(id: u32) -> EhyveCPU {
		EhyveCPU {
			id: id,
			vcpu: vCPU::new().unwrap(),
		}
	}

	fn setup_system_gdt(&mut self) -> Result<()> {
		debug!("Setup GDT");

		self.vcpu
			.write_vmcs(VMCS_GUEST_CS_LIMIT, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_CS_BASE, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_CS_AR, 0x209B)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_SS_LIMIT, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_SS_BASE, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_SS_AR, 0x4093)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_DS_LIMIT, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_DS_BASE, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_DS_AR, 0x4093)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_ES_LIMIT, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_ES_BASE, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_ES_AR, 0x4093)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_FS_LIMIT, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_FS_BASE, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_FS_AR, 0x4093)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_GS_LIMIT, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_GS_BASE, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_GS_AR, 0x4093)
			.or_else(to_error)?;

		self.vcpu
			.write_vmcs(VMCS_GUEST_GDTR_BASE, BOOT_GDT)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(
				VMCS_GUEST_GDTR_LIMIT,
				((std::mem::size_of::<u64>() * BOOT_GDT_MAX as usize) - 1) as u64,
			)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_IDTR_BASE, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_IDTR_LIMIT, 0xffff)
			.or_else(to_error)?;

		self.vcpu.write_vmcs(VMCS_GUEST_TR, 0).or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_TR_LIMIT, 0xffff)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_TR_AR, 0x8b)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_TR_BASE, 0)
			.or_else(to_error)?;

		self.vcpu.write_vmcs(VMCS_GUEST_LDTR, 0).or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_LDTR_LIMIT, 0xffff)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_LDTR_AR, 0x82)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_LDTR_BASE, 0)
			.or_else(to_error)?;
		// Reload the segment descriptors
		self.vcpu
			.write_register(
				&x86Reg::CS,
				SegmentSelector::new(GDT_KERNEL_CODE as u16, Ring::Ring0).bits() as u64,
			)
			.or_else(to_error)?;
		self.vcpu
			.write_register(
				&x86Reg::DS,
				SegmentSelector::new(GDT_KERNEL_DATA as u16, Ring::Ring0).bits() as u64,
			)
			.or_else(to_error)?;
		self.vcpu
			.write_register(
				&x86Reg::ES,
				SegmentSelector::new(GDT_KERNEL_DATA as u16, Ring::Ring0).bits() as u64,
			)
			.or_else(to_error)?;
		self.vcpu
			.write_register(
				&x86Reg::SS,
				SegmentSelector::new(GDT_KERNEL_DATA as u16, Ring::Ring0).bits() as u64,
			)
			.or_else(to_error)?;
		self.vcpu
			.write_register(
				&x86Reg::FS,
				SegmentSelector::new(GDT_KERNEL_DATA as u16, Ring::Ring0).bits() as u64,
			)
			.or_else(to_error)?;
		self.vcpu
			.write_register(
				&x86Reg::GS,
				SegmentSelector::new(GDT_KERNEL_DATA as u16, Ring::Ring0).bits() as u64,
			)
			.or_else(to_error)?;

		Ok(())
	}

	fn setup_system_64bit(&mut self) -> Result<()> {
		debug!("Setup 64bit mode");

		let cr0 = Cr0::CR0_PROTECTED_MODE
			| Cr0::CR0_ENABLE_PAGING
			| Cr0::CR0_EXTENSION_TYPE
			| Cr0::CR0_NUMERIC_ERROR;
		let cr4 = Cr4::CR4_ENABLE_PAE;

		self.vcpu
			.write_vmcs(VMCS_GUEST_IA32_EFER, EFER_LME | EFER_LMA)
			.or_else(to_error)?;

		self.vcpu
			.write_vmcs(
				VMCS_CTRL_CR0_MASK,
				(Cr0::CR0_CACHE_DISABLE | Cr0::CR0_NOT_WRITE_THROUGH | cr0).bits() as u64,
			)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_CTRL_CR0_SHADOW, cr0.bits() as u64)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_CTRL_CR4_MASK, (Cr4::CR4_ENABLE_VMX | cr4).bits() as u64)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_CTRL_CR4_SHADOW, cr4.bits() as u64)
			.or_else(to_error)?;

		self.vcpu
			.write_register(&x86Reg::CR0, cr0.bits() as u64)
			.or_else(to_error)?;
		self.vcpu
			.write_register(&x86Reg::CR4, cr4.bits() as u64)
			.or_else(to_error)?;
		self.vcpu
			.write_register(&x86Reg::CR3, BOOT_PML4)
			.or_else(to_error)?;
		self.vcpu
			.write_register(&x86Reg::DR7, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_SYSENTER_ESP, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_SYSENTER_EIP, 0)
			.or_else(to_error)?;

		Ok(())
	}

	fn setup_msr(&mut self) -> Result<()> {
		const IA32_CSTAR: u32 = 0xc0000083;

		debug!("Enable MSR registers");

		self.vcpu
			.enable_native_msr(IA32_FS_BASE, true)
			.or_else(to_error)?;
		self.vcpu
			.enable_native_msr(IA32_GS_BASE, true)
			.or_else(to_error)?;
		self.vcpu
			.enable_native_msr(IA32_KERNEL_GSBASE, true)
			.or_else(to_error)?;
		self.vcpu
			.enable_native_msr(IA32_SYSENTER_CS, true)
			.or_else(to_error)?;
		self.vcpu
			.enable_native_msr(IA32_SYSENTER_EIP, true)
			.or_else(to_error)?;
		self.vcpu
			.enable_native_msr(IA32_SYSENTER_ESP, true)
			.or_else(to_error)?;
		self.vcpu
			.enable_native_msr(IA32_STAR, true)
			.or_else(to_error)?;
		self.vcpu
			.enable_native_msr(IA32_LSTAR, true)
			.or_else(to_error)?;
		self.vcpu
			.enable_native_msr(IA32_CSTAR, true)
			.or_else(to_error)?;
		self.vcpu
			.enable_native_msr(IA32_FMASK, true)
			.or_else(to_error)?;
		self.vcpu
			.enable_native_msr(TSC, true)
			.or_else(to_error)?;
		self.vcpu
			.enable_native_msr(IA32_TSC_AUX, true)
			.or_else(to_error)?;

		Ok(())
	}

	fn setup_capabilities(&mut self) -> Result<()> {
		debug!("Setup VMX capabilities");

		self.vcpu
			.write_vmcs(VMCS_CTRL_PIN_BASED, *CAP_PINBASED)
			.or_else(to_error)?;
		debug!(
			"Pin-Based VM-Execution Controls 0x{:x}",
			self.vcpu.read_vmcs(VMCS_CTRL_PIN_BASED).unwrap()
		);
		self.vcpu
			.write_vmcs(VMCS_CTRL_CPU_BASED, *CAP_PROCBASED)
			.or_else(to_error)?;
		debug!(
			"Primary Processor-Based VM-Execution Controls 0x{:x}",
			self.vcpu.read_vmcs(VMCS_CTRL_CPU_BASED).unwrap()
		);
		self.vcpu
			.write_vmcs(VMCS_CTRL_CPU_BASED2, *CAP_PROCBASED2)
			.or_else(to_error)?;
		debug!(
			"Secondary Processor-Based VM-Execution Controls 0x{:x}",
			self.vcpu.read_vmcs(VMCS_CTRL_CPU_BASED2).unwrap()
		);
		self.vcpu
			.write_vmcs(VMCS_CTRL_VMENTRY_CONTROLS, *CAP_ENTRY)
			.or_else(to_error)?;
		debug!(
			"VM-Entry Controls 0x{:x}",
			self.vcpu.read_vmcs(VMCS_CTRL_VMENTRY_CONTROLS).unwrap()
		);
		self.vcpu
			.write_vmcs(VMCS_CTRL_VMEXIT_CONTROLS, *CAP_EXIT)
			.or_else(to_error)?;
		debug!(
			"VM-Exit Controls 0x{:x}",
			self.vcpu.read_vmcs(VMCS_CTRL_VMEXIT_CONTROLS).unwrap()
		);

		Ok(())
	}
}

impl VirtualCPU for EhyveCPU {
	fn init(&mut self, entry_point: u64) -> Result<()> {
		self.setup_capabilities()?;
		self.setup_msr()?;

		self.vcpu
			.write_vmcs(VMCS_CTRL_EXC_BITMAP, 0) /* Double fault */
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_CTRL_TPR_THRESHOLD, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_LINK_POINTER, !0x0u64)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_SYSENTER_EIP, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_vmcs(VMCS_GUEST_SYSENTER_ESP, 0)
			.or_else(to_error)?;

		debug!("Setup general purpose registers");
		self.vcpu
			.write_register(&x86Reg::RIP, entry_point)
			.or_else(to_error)?;
		self.vcpu
			.write_register(&x86Reg::RFLAGS, 0x2)
			.or_else(to_error)?;
		// create temporary stack to boot the kernel
		self.vcpu
			.write_register(&x86Reg::RSP, 0x200000 - 0x1000)
			.or_else(to_error)?;
		self.vcpu
			.write_register(&x86Reg::RBP, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_register(&x86Reg::RAX, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_register(&x86Reg::RBX, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_register(&x86Reg::RCX, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_register(&x86Reg::RDX, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_register(&x86Reg::RSI, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_register(&x86Reg::RDI, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_register(&x86Reg::R8, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_register(&x86Reg::R9, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_register(&x86Reg::R10, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_register(&x86Reg::R11, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_register(&x86Reg::R12, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_register(&x86Reg::R13, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_register(&x86Reg::R14, 0)
			.or_else(to_error)?;
		self.vcpu
			.write_register(&x86Reg::R15, 0)
			.or_else(to_error)?;
		self.setup_system_gdt()?;
		self.setup_system_64bit()?;

		Ok(())
	}

	fn run(&mut self) -> Result<()> {
		//self.print_registers();

		debug!("Run vCPU {}", self.id);
		loop {
			self.vcpu.run().or_else(to_error)?;

			let reason = self.vcpu.read_vmcs(VMCS_RO_EXIT_REASON).expect("read vmcs error") & 0xffff;

			match reason {
				vmx_exit::VMX_REASON_VMENTRY_GUEST => {
					error!(
						"Exit reason {} - VM-entry failure due to invalid guest state",
						reason
					);
					self.print_registers();
					return Err(Error::InternalError);
				}
				vmx_exit::VMX_REASON_IO => {
					let qualification = self.vcpu.read_vmcs(VMCS_RO_EXIT_QUALIFIC).unwrap();
					//let len = self.vcpu.read_vmcs(VMCS_RO_VMEXIT_INSTR_LEN).unwrap();

					info!("qualification 0x{:x}", qualification);
				}
				_ => {
					error!("Unhandled exit: {}", reason);
					//self.print_registers();
					return Err(Error::UnhandledExitReason);
				}
			}
		}
	}

	fn print_registers(&self) {
		println!("\nDump state of CPU {}", self.id);
		println!("VMCS:");
		println!("-----");
		println!("CR0: mask {:016x}  shadow {:016x}",
			self.vcpu.read_vmcs(VMCS_CTRL_CR0_MASK).unwrap(),
			self.vcpu.read_vmcs(VMCS_CTRL_CR0_SHADOW).unwrap());
		println!("CR4: mask {:016x}  shadow {:016x}",
			self.vcpu.read_vmcs(VMCS_CTRL_CR4_MASK).unwrap(),
			self.vcpu.read_vmcs(VMCS_CTRL_CR4_SHADOW).unwrap());
		println!("Pinbased: {:016x}\n1st:      {:016x}\n2nd:      {:016x}",
			self.vcpu.read_vmcs(VMCS_CTRL_PIN_BASED).unwrap(),
			self.vcpu.read_vmcs(VMCS_CTRL_CPU_BASED).unwrap(),
			self.vcpu.read_vmcs(VMCS_CTRL_CPU_BASED2).unwrap());
		println!("Entry:    {:016x}\nExit:     {:016x}",
			self.vcpu.read_vmcs(VMCS_CTRL_VMENTRY_CONTROLS).unwrap(),
			self.vcpu.read_vmcs(VMCS_CTRL_VMEXIT_CONTROLS).unwrap());

		println!("\nRegisters:");
		println!("----------");

		let rip = self.vcpu.read_register(&x86Reg::RIP).unwrap();
		let rflags = self.vcpu.read_register(&x86Reg::RFLAGS).unwrap();
		let rsp = self.vcpu.read_register(&x86Reg::RSP).unwrap();
		let rbp = self.vcpu.read_register(&x86Reg::RBP).unwrap();
		let rax = self.vcpu.read_register(&x86Reg::RAX).unwrap();
		let rbx = self.vcpu.read_register(&x86Reg::RBX).unwrap();
		let rcx = self.vcpu.read_register(&x86Reg::RCX).unwrap();
		let rdx = self.vcpu.read_register(&x86Reg::RDX).unwrap();
		let rsi = self.vcpu.read_register(&x86Reg::RSI).unwrap();
		let rdi = self.vcpu.read_register(&x86Reg::RDI).unwrap();
		let r8 = self.vcpu.read_register(&x86Reg::R8).unwrap();
		let r9 = self.vcpu.read_register(&x86Reg::R9).unwrap();
		let r10 = self.vcpu.read_register(&x86Reg::R10).unwrap();
		let r11 = self.vcpu.read_register(&x86Reg::R11).unwrap();
		let r12 = self.vcpu.read_register(&x86Reg::R12).unwrap();
		let r13 = self.vcpu.read_register(&x86Reg::R13).unwrap();
		let r14 = self.vcpu.read_register(&x86Reg::R14).unwrap();
		let r15 = self.vcpu.read_register(&x86Reg::R15).unwrap();

		print!(
			"rip: {:016x}   rsp: {:016x} flags: {:016x}\n\
			rax: {:016x}   rbx: {:016x}   rcx: {:016x}\n\
			rdx: {:016x}   rsi: {:016x}   rdi: {:016x}\n\
			rbp: {:016x}    r8: {:016x}    r9: {:016x}\n\
			r10: {:016x}   r11: {:016x}   r12: {:016x}\n\
			r13: {:016x}   r14: {:016x}   r15: {:016x}\n",
			rip,
			rsp,
			rflags,
			rax,
			rbx,
			rcx,
			rdx,
			rsi,
			rdi,
			rbp,
			r8,
			r9,
			r10,
			r11,
			r12,
			r13,
			r14,
			r15
		);

		let cr0 = self.vcpu.read_register(&x86Reg::CR0).unwrap();
		let cr2 = self.vcpu.read_register(&x86Reg::CR2).unwrap();
		let cr3 = self.vcpu.read_register(&x86Reg::CR3).unwrap();
		let cr4 = self.vcpu.read_register(&x86Reg::CR4).unwrap();
		let efer = self.vcpu.read_vmcs(VMCS_GUEST_IA32_EFER).unwrap();

		println!(
			"cr0: {:016x}   cr2: {:016x}   cr3: {:016x}\ncr4: {:016x}  efer: {:016x}",
			cr0, cr2, cr3, cr4, efer
		);

		println!("\nSegment registers:");
		println!("------------------");
		println!("register  selector  base              limit     type  p dpl db s l g avl");

		let cs = self.vcpu.read_register(&x86Reg::CS).unwrap();
		let ds = self.vcpu.read_register(&x86Reg::DS).unwrap();
		let es = self.vcpu.read_register(&x86Reg::ES).unwrap();
		let ss = self.vcpu.read_register(&x86Reg::SS).unwrap();
		let fs = self.vcpu.read_register(&x86Reg::FS).unwrap();
		let gs = self.vcpu.read_register(&x86Reg::GS).unwrap();
		let tr = self.vcpu.read_register(&x86Reg::TR).unwrap();
		let ldtr = self.vcpu.read_register(&x86Reg::LDTR).unwrap();

		let cs_limit = self.vcpu.read_vmcs(VMCS_GUEST_CS_LIMIT).unwrap();
		let cs_base = self.vcpu.read_vmcs(VMCS_GUEST_CS_BASE).unwrap();
		let cs_ar = self.vcpu.read_vmcs(VMCS_GUEST_CS_AR).unwrap();
		let ss_limit = self.vcpu.read_vmcs(VMCS_GUEST_SS_LIMIT).unwrap();
		let ss_base = self.vcpu.read_vmcs(VMCS_GUEST_SS_BASE).unwrap();
		let ss_ar = self.vcpu.read_vmcs(VMCS_GUEST_SS_AR).unwrap();
		let ds_limit = self.vcpu.read_vmcs(VMCS_GUEST_DS_LIMIT).unwrap();
		let ds_base = self.vcpu.read_vmcs(VMCS_GUEST_DS_BASE).unwrap();
		let ds_ar = self.vcpu.read_vmcs(VMCS_GUEST_DS_AR).unwrap();
		let es_limit = self.vcpu.read_vmcs(VMCS_GUEST_ES_LIMIT).unwrap();
		let es_base = self.vcpu.read_vmcs(VMCS_GUEST_ES_BASE).unwrap();
		let es_ar = self.vcpu.read_vmcs(VMCS_GUEST_ES_AR).unwrap();
		let fs_limit = self.vcpu.read_vmcs(VMCS_GUEST_FS_LIMIT).unwrap();
		let fs_base = self.vcpu.read_vmcs(VMCS_GUEST_FS_BASE).unwrap();
		let fs_ar = self.vcpu.read_vmcs(VMCS_GUEST_FS_AR).unwrap();
		let gs_limit = self.vcpu.read_vmcs(VMCS_GUEST_GS_LIMIT).unwrap();
		let gs_base = self.vcpu.read_vmcs(VMCS_GUEST_GS_BASE).unwrap();
		let gs_ar = self.vcpu.read_vmcs(VMCS_GUEST_GS_AR).unwrap();
		let tr_limit = self.vcpu.read_vmcs(VMCS_GUEST_TR_LIMIT).unwrap();
		let tr_base = self.vcpu.read_vmcs(VMCS_GUEST_TR_BASE).unwrap();
		let tr_ar = self.vcpu.read_vmcs(VMCS_GUEST_TR_AR).unwrap();
		let ldtr_limit = self.vcpu.read_vmcs(VMCS_GUEST_LDTR_LIMIT).unwrap();
		let ldtr_base = self.vcpu.read_vmcs(VMCS_GUEST_LDTR_BASE).unwrap();
		let ldtr_ar = self.vcpu.read_vmcs(VMCS_GUEST_LDTR_AR).unwrap();

		/*
		 * Format of Access Rights
		 * -----------------------
		 * 3-0 : Segment type
		 * 4   : S — Descriptor type (0 = system; 1 = code or data)
		 * 6-5 : DPL — Descriptor privilege level
		 * 7   : P — Segment present
		 * 11-8: Reserved
		 * 12  : AVL — Available for use by system software
		 * 13  : L — 64-bit mode active (for CS only)
		 * 14  : D/B — Default operation size (0 = 16-bit segment; 1 = 32-bit segment)
		 * 15  : G — Granularity
		 * 16  : Segment unusable (0 = usable; 1 = unusable)
		 *
		 * Output sequence: type p dpl db s l g avl
		 */
		println!("cs        {:04x}      {:016x}  {:08x}  {:02x}    {:x} {:x}   {:x}  {:x} {:x} {:x} {:x}",
			cs, cs_base, cs_limit, (cs_ar) & 0xf, (cs_ar >> 7) & 0x1, (cs_ar >> 5) & 0x3, (cs_ar >> 14) & 0x1,
			(cs_ar >> 4) & 0x1, (cs_ar >> 13) & 0x1, (cs_ar >> 15) & 0x1, (cs_ar >> 12) & 1);
		println!("ss        {:04x}      {:016x}  {:08x}  {:02x}    {:x} {:x}   {:x}  {:x} {:x} {:x} {:x}",
			ss, ss_base, ss_limit, (ss_ar) & 0xf, (ss_ar >> 7) & 0x1, (ss_ar >> 5) & 0x3, (ss_ar >> 14) & 0x1,
			(ss_ar >> 4) & 0x1, (ss_ar >> 13) & 0x1, (ss_ar >> 15) & 0x1, (ss_ar >> 12) & 1);
		println!("ds        {:04x}      {:016x}  {:08x}  {:02x}    {:x} {:x}   {:x}  {:x} {:x} {:x} {:x}",
			ds, ds_base, ds_limit, (ds_ar) & 0xf, (ds_ar >> 7) & 0x1, (ds_ar >> 5) & 0x3, (ds_ar >> 14) & 0x1,
			(ds_ar >> 4) & 0x1, (ds_ar >> 13) & 0x1, (ds_ar >> 15) & 0x1, (ds_ar >> 12) & 1);
		println!("es        {:04x}      {:016x}  {:08x}  {:02x}    {:x} {:x}   {:x}  {:x} {:x} {:x} {:x}",
			es, es_base, es_limit, (es_ar) & 0xf, (es_ar >> 7) & 0x1, (es_ar >> 5) & 0x3, (es_ar >> 14) & 0x1,
			(es_ar >> 4) & 0x1, (es_ar >> 13) & 0x1, (es_ar >> 15) & 0x1, (es_ar >> 12) & 1);
		println!("fs        {:04x}      {:016x}  {:08x}  {:02x}    {:x} {:x}   {:x}  {:x} {:x} {:x} {:x}",
			fs, fs_base, fs_limit, (fs_ar) & 0xf, (fs_ar >> 7) & 0x1, (fs_ar >> 5) & 0x3, (fs_ar >> 14) & 0x1,
			(fs_ar >> 4) & 0x1, (fs_ar >> 13) & 0x1, (fs_ar >> 15) & 0x1, (fs_ar >> 12) & 1);
		println!("gs        {:04x}      {:016x}  {:08x}  {:02x}    {:x} {:x}   {:x}  {:x} {:x} {:x} {:x}",
			gs, gs_base, gs_limit, (gs_ar) & 0xf, (gs_ar >> 7) & 0x1, (gs_ar >> 5) & 0x3, (gs_ar >> 14) & 0x1,
			(gs_ar >> 4) & 0x1, (gs_ar >> 13) & 0x1, (gs_ar >> 15) & 0x1, (gs_ar >> 12) & 1);
		println!("tr        {:04x}      {:016x}  {:08x}  {:02x}    {:x} {:x}   {:x}  {:x} {:x} {:x} {:x}",
			tr, tr_base, tr_limit, (tr_ar) & 0xf, (tr_ar >> 7) & 0x1, (tr_ar >> 5) & 0x3, (tr_ar >> 14) & 0x1,
			(tr_ar >> 4) & 0x1, (tr_ar >> 13) & 0x1, (tr_ar >> 15) & 0x1, (tr_ar >> 12) & 1);
		println!("ldt       {:04x}      {:016x}  {:08x}  {:02x}    {:x} {:x}   {:x}  {:x} {:x} {:x} {:x}",
			ldtr, ldtr_base, ldtr_limit, (ldtr_ar) & 0xf, (ldtr_ar >> 7) & 0x1, (ldtr_ar >> 5) & 0x3, (ldtr_ar >> 14) & 0x1,
			(ldtr_ar >> 4) & 0x1, (ldtr_ar >> 13) & 0x1, (ldtr_ar >> 15) & 0x1, (ldtr_ar >> 12) & 1);

		let gdt_base = self.vcpu.read_vmcs(VMCS_GUEST_GDTR_BASE).unwrap();
		let gdt_limit = self.vcpu.read_vmcs(VMCS_GUEST_GDTR_LIMIT).unwrap();
		println!("gdt                 {:016x}  {:08x}", gdt_base, gdt_limit);
		let idt_base = self.vcpu.read_vmcs(VMCS_GUEST_IDTR_BASE).unwrap();
		let idt_limit = self.vcpu.read_vmcs(VMCS_GUEST_IDTR_LIMIT).unwrap();
		println!("idt                 {:016x}  {:08x}", idt_base, idt_limit);
		println!("VMCS link pointer   {:016x}", self.vcpu.read_vmcs(VMCS_GUEST_LINK_POINTER).unwrap());
	}
}

impl Drop for EhyveCPU {
	fn drop(&mut self) {
		debug!("Drop virtual CPU {}", self.id);
		let _ = self.vcpu.destroy();
	}
}
