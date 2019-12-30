pub mod ehyve;
pub mod vcpu;

use kvm_ioctls::Kvm;

lazy_static! {
	static ref KVM: Kvm = { Kvm::new().unwrap() };
}
