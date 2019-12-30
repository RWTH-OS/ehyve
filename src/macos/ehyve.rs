use error::*;
use libc;
use libc::c_void;
use macos::vcpu::*;
use memmap::MmapOptions;
use std;
use std::fs::File;
use vm::{VirtualCPU, Vm};
use xhypervisor::{create_vm, map_mem, unmap_mem, MemPerm};

pub struct Ehyve {
	entry_point: u64,
	mem_size: usize,
	guest_mem: *mut c_void,
	file_mmap: Option<memmap::Mmap>,
	num_cpus: u32,
	path: String,
}

impl Ehyve {
	pub fn new(
		path: String,
		mem_size: usize,
		num_cpus: u32,
		file_path: Option<String>,
	) -> Result<Ehyve> {
		let mem = unsafe {
			libc::mmap(
				std::ptr::null_mut(),
				mem_size,
				libc::PROT_READ | libc::PROT_WRITE,
				libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_NORESERVE,
				-1,
				0,
			)
		};

		if mem == libc::MAP_FAILED {
			error!("mmap failed with");
			return Err(Error::NotEnoughMemory);
		}

		debug!("Allocate memory for the guest at 0x{:x}", mem as usize);

		debug!("Create VM...");
		create_vm().or_else(to_error)?;

		debug!("Map guest memory...");
		unsafe {
			map_mem(
				std::slice::from_raw_parts(mem as *mut u8, mem_size),
				0,
				&MemPerm::ExecAndWrite,
			)
			.or_else(to_error)?;
		}

		let file_mmap = match &file_path {
			Some(fname) => {
				debug!("Map {} into the guest space", fname);

				let f = File::open(fname.clone())
					.map_err(|_| Error::InvalidFile(fname.clone().into()))?;
				
				let mmap = unsafe { MmapOptions::new().map(&f).unwrap() };

				info!("File is mapped at address 0x{:x}", mmap.as_ptr() as u64);
			
				unsafe {
					map_mem(
						std::slice::from_raw_parts(mmap.as_ptr(), mmap.len()),
						mem_size as u64,
						&MemPerm::Read,
					)
					.or_else(to_error)?;
				}
				Some(mmap)
			}
			None => {
				None
			}
		};

		let hyve = Ehyve {
			entry_point: 0,
			mem_size: mem_size,
			guest_mem: mem,
			file_mmap: file_mmap,
			num_cpus: num_cpus,
			path: path,
		};

		hyve.init_guest_mem();

		Ok(hyve)
	}
}

impl Vm for Ehyve {
	fn set_entry_point(&mut self, entry: u64) {
		self.entry_point = entry;
	}

	fn get_entry_point(&self) -> u64 {
		self.entry_point
	}

	fn num_cpus(&self) -> u32 {
		self.num_cpus
	}

	fn guest_mem(&self) -> (*mut u8, usize) {
		(self.guest_mem as *mut u8, self.mem_size)
	}

	fn kernel_path(&self) -> &str {
		&self.path
	}

	fn create_cpu(&self, id: u32) -> Result<Box<dyn VirtualCPU>> {
		Ok(Box::new(EhyveCPU::new(id)))
	}

	fn file(&self) -> (u64, u64) {
		// do we mount a file into the guest memory?
		match &self.file_mmap {
			Some(mmap) => {
				(self.mem_size as u64, mmap.len() as u64)
			}
			_ => {
				(0, 0)
			}
		}
	}
}

impl Drop for Ehyve {
	fn drop(&mut self) {
		debug!("Drop virtual machine");

		unmap_mem(0, self.mem_size).unwrap();

		// do we mount a file into the guest memory?
		match &self.file_mmap {
			Some(mmap) => {
				unmap_mem(self.mem_size as u64, mmap.len()).unwrap();
			}
			_ => {}
		}

		unsafe {
			libc::munmap(self.guest_mem, self.mem_size);
		}
	}
}

unsafe impl Send for Ehyve {}
unsafe impl Sync for Ehyve {}
