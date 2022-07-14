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

use clap::{App, Arg};
use consts::*;
use std::env;
use std::sync::Arc;
use std::thread;
use vm::*;

pub fn parse_bool(name: &str, default: bool) -> bool {
	env::var(name)
		.map(|x| x.parse::<i32>().unwrap_or(default as i32) != 0)
		.unwrap_or(default)
}

fn main() {
	env_logger::init();

	let matches = App::new("eHyve")
		.version(crate_version!())
		.author("Stefan Lankes <slankes@eonerc.rwth-aachen.de>")
		.about("A minimal hypervisor for eduOS-rs")
		.arg(
			Arg::with_name("FILE")
				.short("f")
				.long("file")
				.value_name("FILE")
				.help("Map FILE into the address space of the guest")
				.takes_value(true),
		)
		.arg(
			Arg::with_name("MEM")
				.short("m")
				.long("memsize")
				.value_name("MEM")
				.help("Memory size of the guest")
				.takes_value(true),
		)
		.arg(
			Arg::with_name("CPUS")
				.short("c")
				.long("cpus")
				.value_name("CPUS")
				.help("Number of guest processors")
				.takes_value(true),
		)
		.arg(
			Arg::with_name("KERNEL")
				.help("Sets path to the kernel")
				.required(true)
				.index(1),
		)
		.get_matches();

	let path = matches
		.value_of("KERNEL")
		.expect("Expect path to the kernel!");
	let file = matches.value_of("FILE").map(str::to_string);
	let mem_size: usize = matches
		.value_of("MEM")
		.map(|x| utils::parse_mem(&x).expect("couldn't parse --memsize"))
		.unwrap_or(DEFAULT_GUEST_SIZE);
	let num_cpus: u32 = matches
		.value_of("CPUS")
		.map(|x| utils::parse_u32(&x).unwrap_or(1))
		.unwrap_or(1);

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
