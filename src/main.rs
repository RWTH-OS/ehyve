#![feature(untagged_unions)]
#![feature(core_intrinsics)]
#![allow(dead_code)]

extern crate elf;
extern crate libc;
extern crate memmap;
extern crate x86;
#[macro_use]
extern crate clap;
#[macro_use]
extern crate lazy_static;
#[cfg(target_os = "linux")]
extern crate kvm_bindings;
#[cfg(target_os = "linux")]
extern crate kvm_ioctls;
#[cfg(target_os = "windows")]
extern crate libwhp;
#[cfg(target_os = "macos")]
extern crate xhypervisor;
//#[cfg(target_os = "windows")]
//extern crate kernel32;

#[macro_use]
extern crate log;
extern crate env_logger;

pub mod consts;
pub mod error;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
pub mod utils;
mod vm;
#[cfg(target_os = "windows")]
mod windows;

use clap::Parser;
use consts::*;
use std::env;
use std::sync::Arc;
use std::thread;
use vm::*;

/// A minimal hypervisor for eduOS-rs
#[derive(Parser, Debug)]
#[command(author=crate_authors!(), version, about, long_about = None)]
struct Args {
	/// Map file into the address space of the guest
	#[arg(short, long)]
	file: Option<String>,

	/// Memory size of the guest
	#[arg(short, long, default_value_t = DEFAULT_GUEST_SIZE)]
	mem_size: usize,

	/// Number of guest processors
	#[arg(short, long, default_value_t = 1)]
	num_cpus: u32,

	/// Expected path to the kernel
	path: String,
}

pub fn parse_bool(name: &str, default: bool) -> bool {
	env::var(name)
		.map(|x| x.parse::<i32>().unwrap_or(default as i32) != 0)
		.unwrap_or(default)
}

fn main() {
	env_logger::init();
	let args = Args::parse();
	let path = args.path;
	let file = args.file;
	let mem_size = args.mem_size;
	let num_cpus = args.num_cpus;

	let mut vm = create_vm(path.to_string(), VmParameter::new(mem_size, num_cpus, file)).unwrap();
	let num_cpus = vm.num_cpus();

	vm.load_kernel().unwrap();

	let vm = Arc::new(vm);
	let threads: Vec<_> = (0..num_cpus)
		.map(|tid| {
			let vm = vm.clone();

			thread::spawn(move || {
				debug!("Create thread for CPU {}", tid);

				let mut cpu = vm.create_cpu(tid).unwrap();
				cpu.init(vm.get_entry_point()).unwrap();

				let result = cpu.run();
				match result {
					Ok(ret_code) => {
						if ret_code != 0 {
							std::process::exit(ret_code as i32);
						}
					}
					Err(x) => {
						error!("CPU {} crashes! {}", tid, x);
						std::process::exit(255);
					}
				}
			})
		})
		.collect();

	for t in threads {
		t.join().unwrap();
	}
}
