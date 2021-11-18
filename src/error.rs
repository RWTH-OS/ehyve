use std::{fmt, result};
#[cfg(target_os = "macos")]
use xhypervisor;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, Clone)]
pub enum Error {
	FileMissing,
	InternalError,
	OsError(i32),
	InvalidFile(String),
	NotEnoughMemory,
	MissingFrequency,
	#[cfg(target_os = "macos")]
	Hypervisor(xhypervisor::Error),
	UnknownExitReason,
	UnknownIOPort(u16),
	Shutdown,
	ParseMemory,
	UnhandledExitReason,
}

#[cfg(target_os = "linux")]
pub fn to_error<T>(err: kvm_ioctls::Error) -> Result<T> {
	Err(Error::OsError(err.errno()))
}

#[cfg(target_os = "macos")]
impl From<xhypervisor::Error> for Error {
	fn from(err: xhypervisor::Error) -> Self {
		Error::Hypervisor(err)
	}
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			Error::FileMissing => write!(f, "No execution file given"),
			Error::InternalError => write!(f, "An internal error has occurred, please report."),
			Error::OsError(ref err) => write!(f, "Error from OS: {}", err),
			Error::InvalidFile(ref file) => {
				write!(f, "The file {} was not found or is invalid.", file)
			}
			Error::NotEnoughMemory => write!(
				f,
				"The host system has not enough memory, please check your memory usage."
			),
			Error::MissingFrequency => write!(
				f,
				"Couldn't get the CPU frequency from your system. (is /proc/cpuinfo missing?)"
			),
			#[cfg(target_os = "macos")]
			Error::Hypervisor(ref err) => write!(f, "The hypervisor has failed: {:?}", err),
			Error::UnknownExitReason => write!(f, "Unknown exit reason ."),
			Error::UnknownIOPort(ref port) => write!(f, "Unknown io port 0x{:x}.", port),
			Error::Shutdown => write!(f, "Receives shutdown command"),
			Error::ParseMemory => write!(
				f,
				"Couldn't parse the guest memory size from the environment"
			),
			Error::UnhandledExitReason => write!(f, "Unhandled exit reason"),
		}
	}
}
