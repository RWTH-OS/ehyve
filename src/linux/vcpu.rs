use consts::*;
use error::*;
use kvm_bindings::*;
use kvm_ioctls::{VcpuExit, VcpuFd, MAX_KVM_CPUID_ENTRIES};
use linux::KVM;
use std;
use vm::VirtualCPU;
use x86::controlregs::*;

const CPUID_EXT_HYPERVISOR: u32 = 1 << 31;
const CPUID_TSC_DEADLINE: u32 = 1 << 24;
const CPUID_ENABLE_MSR: u32 = 1 << 5;
const MSR_IA32_MISC_ENABLE: u32 = 0x000001a0;

pub struct EhyveCPU {
	id: u32,
	vcpu: VcpuFd,
}

impl EhyveCPU {
	pub fn new(id: u32, vcpu: VcpuFd) -> EhyveCPU {
		EhyveCPU { id: id, vcpu: vcpu }
	}

	fn setup_cpuid(&self) -> Result<()> {
		let mut kvm_cpuid = KVM
			.get_supported_cpuid(MAX_KVM_CPUID_ENTRIES)
			.or_else(to_error)?;
		let kvm_cpuid_entries = kvm_cpuid.as_mut_slice();
		let i = kvm_cpuid_entries
			.iter()
			.position(|&r| r.function == 0x80000002)
			.unwrap();

		// create own processor string (first part)
		let mut id_reg_values: [u32; 4] = [0; 4];
		let id = b"ehyve - a minima";
		unsafe {
			std::ptr::copy_nonoverlapping(
				id.as_ptr(),
				id_reg_values.as_mut_ptr() as *mut u8,
				id.len(),
			);
		}
		kvm_cpuid_entries[i].eax = id_reg_values[0];
		kvm_cpuid_entries[i].ebx = id_reg_values[1];
		kvm_cpuid_entries[i].ecx = id_reg_values[2];
		kvm_cpuid_entries[i].edx = id_reg_values[3];

		let i = kvm_cpuid_entries
			.iter()
			.position(|&r| r.function == 0x80000003)
			.unwrap();

		// create own processor string (second part)
		let id = b"l hypervisor\0";
		unsafe {
			std::ptr::copy_nonoverlapping(
				id.as_ptr(),
				id_reg_values.as_mut_ptr() as *mut u8,
				id.len(),
			);
		}
		kvm_cpuid_entries[i].eax = id_reg_values[0];
		kvm_cpuid_entries[i].ebx = id_reg_values[1];
		kvm_cpuid_entries[i].ecx = id_reg_values[2];
		kvm_cpuid_entries[i].edx = id_reg_values[3];

		let i = kvm_cpuid_entries
			.iter()
			.position(|&r| r.function == 1)
			.unwrap();

		// CPUID to define basic cpu features
		kvm_cpuid_entries[i].ecx |= CPUID_EXT_HYPERVISOR; // propagate that we are running on a hypervisor
		kvm_cpuid_entries[i].ecx |= CPUID_TSC_DEADLINE; // enable TSC deadline feature
		kvm_cpuid_entries[i].edx |= CPUID_ENABLE_MSR; // enable msr support

		let i = kvm_cpuid_entries
			.iter()
			.position(|&r| r.function == 0x0A)
			.unwrap();

		// disable performance monitor
		kvm_cpuid_entries[i].eax = 0x00;

		self.vcpu.set_cpuid2(&kvm_cpuid).or_else(to_error)?;

		Ok(())
	}

	fn setup_msrs(&self) -> Result<()> {
		let msr_list = KVM.get_msr_index_list().or_else(to_error)?;

		let mut msr_entries = msr_list
			.iter()
			.map(|i| kvm_msr_entry {
				index: *i,
				data: 0,
				..Default::default()
			})
			.collect::<Vec<_>>();

		// enable fast string operations
		msr_entries[0].index = MSR_IA32_MISC_ENABLE;
		msr_entries[0].data = 1;

		let mut msrs: &mut kvm_msrs = unsafe { &mut *(msr_entries.as_ptr() as *mut kvm_msrs) };
		msrs.nmsrs = 1;

		self.vcpu.set_msrs(msrs).or_else(to_error)?;

		Ok(())
	}

	fn setup_long_mode(&self, entry_point: u64) -> Result<()> {
		debug!("Setup long mode");

		let mut sregs = self.vcpu.get_sregs().unwrap();

		let cr0 = (Cr0::CR0_PROTECTED_MODE
			| Cr0::CR0_ENABLE_PAGING
			| Cr0::CR0_EXTENSION_TYPE
			| Cr0::CR0_NUMERIC_ERROR)
			.bits() as u64;
		let cr4 = Cr4::CR4_ENABLE_PAE.bits() as u64;

		sregs.cr3 = BOOT_PML4;
		sregs.cr4 = cr4;
		sregs.cr0 = cr0;
		sregs.efer = EFER_LME | EFER_LMA;

		let mut seg = kvm_segment {
			base: 0,
			limit: 0,
			selector: 1 << 3,
			present: 1,
			type_: 11,
			dpl: 0,
			db: 0,
			s: 1,
			l: 1,
			g: 0,
			..Default::default()
		};

		sregs.cs = seg;

		seg.type_ = 3;
		seg.selector = 2 << 3;
		seg.l = 0;
		sregs.ds = seg;
		sregs.es = seg;
		sregs.fs = seg;
		sregs.gs = seg;
		sregs.ss = seg;
		sregs.gdt.base = BOOT_GDT;
		sregs.gdt.limit = ((std::mem::size_of::<u64>() * BOOT_GDT_MAX as usize) - 1) as u16;

		self.vcpu.set_sregs(&sregs).or_else(to_error)?;

		let mut regs = self.vcpu.get_regs().or_else(to_error)?;
		regs.rflags = 2;
		regs.rip = entry_point;
		regs.rsp = 0x200000u64 - 0x1000u64;

		self.vcpu.set_regs(&regs).or_else(to_error)?;

		Ok(())
	}

	fn show_dtable(name: &str, dtable: &kvm_dtable) {
		println!(
			"{}                 {:016x}  {:08x}",
			name, dtable.base, dtable.limit
		);
	}

	fn show_segment(name: &str, seg: &kvm_segment) {
		println!(
			"{}       {:04x}      {:016x}  {:08x}  {:02x}    {:x} {:x}   {:x}  {:x} {:x} {:x} {:x}",
			name,
			seg.selector,
			seg.base,
			seg.limit,
			seg.type_,
			seg.present,
			seg.dpl,
			seg.db,
			seg.s,
			seg.l,
			seg.g,
			seg.avl
		);
	}
}

impl VirtualCPU for EhyveCPU {
	fn init(&mut self, entry_point: u64) -> Result<()> {
		self.setup_long_mode(entry_point)?;
		self.setup_cpuid()?;
		self.setup_msrs()?;

		Ok(())
	}

	fn run(&mut self) -> Result<()> {
		//self.print_registers();

		loop {
			let exitreason = self.vcpu.run().or_else(to_error)?;
			match exitreason {
				VcpuExit::Hlt => {
					info!("Halt Exit");
					break;
				}
				VcpuExit::Shutdown => {
					self.print_registers();
					info!("Shutdown Exit");
					break;
				}
				VcpuExit::IoOut(port, addr) => match port {
					SHUTDOWN_PORT => {
						return Ok(());
					}
					_ => {
						self.io_exit(port, std::str::from_utf8(addr).unwrap().to_string())?;
					}
				},
				_ => {
					error!("Unknown exit reason: {:?}", exitreason);
					//self.print_registers();

					return Err(Error::UnknownExitReason);
				}
			}
		}

		Ok(())
	}

	fn print_registers(&self) {
		let regs = self.vcpu.get_regs().unwrap();
		let sregs = self.vcpu.get_sregs().unwrap();

		println!("\nDump state of CPU {}", self.id);
		println!("\nRegisters:");
		println!("----------");
		print!(
			"rip: {:016x}   rsp: {:016x} flags: {:016x}\n\
			rax: {:016x}   rbx: {:016x}   rcx: {:016x}\n\
			rdx: {:016x}   rsi: {:016x}   rdi: {:016x}\n\
			rbp: {:016x}    r8: {:016x}    r9: {:016x}\n\
			r10: {:016x}   r11: {:016x}   r12: {:016x}\n\
			r13: {:016x}   r14: {:016x}   r15: {:016x}\n",
			regs.rip,
			regs.rsp,
			regs.rflags,
			regs.rax,
			regs.rbx,
			regs.rcx,
			regs.rdx,
			regs.rsi,
			regs.rdi,
			regs.rbp,
			regs.r8,
			regs.r9,
			regs.r10,
			regs.r11,
			regs.r12,
			regs.r13,
			regs.r14,
			regs.r15
		);

		println!(
			"cr0: {:016x}   cr2: {:016x}   cr3: {:016x}\ncr4: {:016x}  efer: {:016x}",
			sregs.cr0, sregs.cr2, sregs.cr3, sregs.cr4, sregs.efer
		);

		println!("\nSegment registers:");
		println!("------------------");
		println!("register  selector  base              limit     type  p dpl db s l g avl");
		EhyveCPU::show_segment("cs ", &sregs.cs);
		EhyveCPU::show_segment("ss ", &sregs.ss);
		EhyveCPU::show_segment("ds ", &sregs.ds);
		EhyveCPU::show_segment("es ", &sregs.es);
		EhyveCPU::show_segment("fs ", &sregs.fs);
		EhyveCPU::show_segment("gs ", &sregs.gs);
		EhyveCPU::show_segment("tr ", &sregs.tr);
		EhyveCPU::show_segment("ldt", &sregs.ldt);
		EhyveCPU::show_dtable("gdt", &sregs.gdt);
		EhyveCPU::show_dtable("idt", &sregs.idt);

		println!("\nAPIC:");
		println!("-----");
		println!("apic: {:016x}", sregs.apic_base);
	}
}

impl Drop for EhyveCPU {
	fn drop(&mut self) {
		debug!("Drop vCPU {}", self.id);
	}
}
