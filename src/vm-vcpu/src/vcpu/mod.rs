// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use std::io::{self, stdin};
use std::result;
use std::sync::{Arc, Mutex};

use kvm_bindings::{
    kvm_fpu, kvm_regs, kvm_translation,
    kvm_xen_exit__bindgen_ty_1__bindgen_ty_1 as kvm_xen_exit_hcall, kvm_xen_hvm_attr, CpuId, Msrs,
};
use kvm_ioctls::{VcpuExit, VcpuFd, VmFd, XenExit};
use log::trace;
use vm_device::bus::{MmioAddress, PioAddress};
use vm_device::device_manager::{IoManager, MmioManager, PioManager};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryMmap};
use vmm_sys_util::terminal::Terminal;

mod gdt;
use gdt::*;
mod interrupts;
use interrupts::*;

pub mod cpuid;
pub mod mpspec;
pub mod mptable;
pub mod msr_index;
pub mod msrs;

/// Initial stack for the boot CPU.
const BOOT_STACK_POINTER: u64 = 0x8ff0;
/// Address of the zeropage, where Linux kernel boot parameters are written.
const ZEROPG_START: u64 = 0x7000;

// Initial pagetables.
const PML4_START: u64 = 0x9000;
const PDPTE_START: u64 = 0xa000;
const PDE_START: u64 = 0xb000;

const X86_CR0_PE: u64 = 0x1;
const X86_CR0_PG: u64 = 0x8000_0000;
const X86_CR4_PAE: u64 = 0x20;

/// Errors encountered during vCPU operation.
#[derive(Debug)]
pub enum Error {
    /// Failed to operate on guest memory.
    GuestMemory(GuestMemoryError),
    /// I/O Error.
    IO(io::Error),
    /// Error issuing an ioctl to KVM.
    KvmIoctl(kvm_ioctls::Error),
    /// Failed to configure mptables.
    Mptable(mptable::Error),
    /// Failed to configure MSRs.
    SetModelSpecificRegistersCount,
}

/// Dedicated Result type.
pub type Result<T> = result::Result<T, Error>;

pub struct VcpuState {
    pub id: u8,
    pub cpuid: CpuId,
}

const DOMID_SELF: u16 = 0x7ff0;

#[derive(Copy, Clone, Default, Debug)]
#[repr(C)]
struct xen_hvm_param {
    domid: u16, /* IN */
    index: u32, /* IN */
    value: u64, /* IN/OUT */
}

/// Struct for interacting with vCPUs.
///
/// This struct is a temporary (and quite terrible) placeholder until the
/// [`vmm-vcpu`](https://github.com/rust-vmm/vmm-vcpu) crate is stabilized.
pub struct KvmVcpu {
    vm_fd: Arc<VmFd>,
    /// KVM file descriptor for a vCPU.
    vcpu_fd: VcpuFd,
    /// Device manager for bus accesses.
    device_mgr: Arc<Mutex<IoManager>>,
    state: VcpuState,
    running: bool,
    // Temporarily adding this here while experimenting with Xen stuff.
    mem: GuestMemoryMmap,
}

impl KvmVcpu {
    /// Create a new vCPU.
    pub fn new(
        vm_fd: Arc<VmFd>,
        device_mgr: Arc<Mutex<IoManager>>,
        state: VcpuState,
        memory: &GuestMemoryMmap,
    ) -> Result<Self> {
        let vcpu_fd = vm_fd.create_vcpu(state.id).map_err(Error::KvmIoctl)?;
        let vcpu = KvmVcpu {
            vm_fd,
            vcpu_fd,
            device_mgr,
            state,
            running: false,
            mem: memory.clone(),
        };

        vcpu.configure_cpuid(&vcpu.state.cpuid)?;
        vcpu.configure_msrs()?;
        vcpu.configure_sregs(memory)?;
        vcpu.configure_lapic()?;
        vcpu.configure_fpu()?;
        Ok(vcpu)
    }

    /// Set CPUID.
    fn configure_cpuid(&self, cpuid: &CpuId) -> Result<()> {
        self.vcpu_fd.set_cpuid2(cpuid).map_err(Error::KvmIoctl)
    }

    /// Configure MSRs.
    fn configure_msrs(&self) -> Result<()> {
        let entry_vec = msrs::create_boot_msr_entries();
        let msrs = Msrs::from_entries(&entry_vec);
        self.vcpu_fd
            .set_msrs(&msrs)
            .map_err(Error::KvmIoctl)
            .and_then(|msrs_written| {
                if msrs_written as u32 != msrs.as_fam_struct_ref().nmsrs {
                    Err(Error::SetModelSpecificRegistersCount)
                } else {
                    Ok(())
                }
            })
    }

    /// Configure regs.
    fn configure_regs(&self, instruction_pointer: GuestAddress) -> Result<()> {
        let regs = kvm_regs {
            // EFLAGS (RFLAGS in 64-bit mode) always has bit 1 set.
            // See https://software.intel.com/sites/default/files/managed/39/c5/325462-sdm-vol-1-2abcd-3abcd.pdf#page=79
            // Section "EFLAGS Register"
            rflags: 0x0000_0000_0000_0002u64,
            rip: instruction_pointer.raw_value(),
            // Starting stack pointer.
            rsp: BOOT_STACK_POINTER,
            // Frame pointer. It gets a snapshot of the stack pointer (rsp) so that when adjustments are
            // made to rsp (i.e. reserving space for local variables or pushing values on to the stack),
            // local variables and function parameters are still accessible from a constant offset from rbp.
            rbp: BOOT_STACK_POINTER,
            // Must point to zero page address per Linux ABI. This is x86_64 specific.
            rsi: ZEROPG_START,
            ..Default::default()
        };
        self.vcpu_fd.set_regs(&regs).map_err(Error::KvmIoctl)
    }

    /// Configure sregs.
    fn configure_sregs<M: GuestMemory>(&self, guest_memory: &M) -> Result<()> {
        let mut sregs = self.vcpu_fd.get_sregs().map_err(Error::KvmIoctl)?;

        // Global descriptor tables.
        let gdt_table: [u64; BOOT_GDT_MAX as usize] = [
            gdt_entry(0, 0, 0),            // NULL
            gdt_entry(0xa09b, 0, 0xfffff), // CODE
            gdt_entry(0xc093, 0, 0xfffff), // DATA
            gdt_entry(0x808b, 0, 0xfffff), // TSS
        ];

        let code_seg = kvm_segment_from_gdt(gdt_table[1], 1);
        let data_seg = kvm_segment_from_gdt(gdt_table[2], 2);
        let tss_seg = kvm_segment_from_gdt(gdt_table[3], 3);

        // Write segments to guest memory.
        write_gdt_table(&gdt_table[..], guest_memory).map_err(Error::GuestMemory)?;
        sregs.gdt.base = BOOT_GDT_OFFSET as u64;
        sregs.gdt.limit = std::mem::size_of_val(&gdt_table) as u16 - 1;

        write_idt_value(0, guest_memory).map_err(Error::GuestMemory)?;
        sregs.idt.base = BOOT_IDT_OFFSET as u64;
        sregs.idt.limit = std::mem::size_of::<u64>() as u16 - 1;

        sregs.cs = code_seg;
        sregs.ds = data_seg;
        sregs.es = data_seg;
        sregs.fs = data_seg;
        sregs.gs = data_seg;
        sregs.ss = data_seg;
        sregs.tr = tss_seg;

        // 64-bit protected mode.
        sregs.cr0 |= X86_CR0_PE;
        sregs.efer |= (msr_index::EFER_LME | msr_index::EFER_LMA) as u64;

        // Start page table configuration.
        // Puts PML4 right after zero page but aligned to 4k.
        let boot_pml4_addr = GuestAddress(PML4_START);
        let boot_pdpte_addr = GuestAddress(PDPTE_START);
        let boot_pde_addr = GuestAddress(PDE_START);

        // Entry covering VA [0..512GB).
        guest_memory
            .write_obj(boot_pdpte_addr.raw_value() | 0x03, boot_pml4_addr)
            .map_err(Error::GuestMemory)?;

        // Entry covering VA [0..1GB).
        guest_memory
            .write_obj(boot_pde_addr.raw_value() | 0x03, boot_pdpte_addr)
            .map_err(Error::GuestMemory)?;

        // 512 2MB entries together covering VA [0..1GB).
        // This assumes that the CPU supports 2MB pages (/proc/cpuinfo has 'pse').
        for i in 0..512 {
            guest_memory
                .write_obj((i << 21) + 0x83u64, boot_pde_addr.unchecked_add(i * 8))
                .map_err(Error::GuestMemory)?;
        }

        sregs.cr3 = boot_pml4_addr.raw_value();
        sregs.cr4 |= X86_CR4_PAE;
        sregs.cr0 |= X86_CR0_PG;

        self.vcpu_fd.set_sregs(&sregs).map_err(Error::KvmIoctl)
    }

    /// Configure FPU.
    fn configure_fpu(&self) -> Result<()> {
        let fpu = kvm_fpu {
            fcw: 0x37f,
            mxcsr: 0x1f80,
            ..Default::default()
        };
        self.vcpu_fd.set_fpu(&fpu).map_err(Error::KvmIoctl)
    }

    /// Configures LAPICs. LAPIC0 is set for external interrupts, LAPIC1 is set for NMI.
    fn configure_lapic(&self) -> Result<()> {
        let mut klapic = self.vcpu_fd.get_lapic().map_err(Error::KvmIoctl)?;

        let lvt_lint0 = get_klapic_reg(&klapic, APIC_LVT0);
        set_klapic_reg(
            &mut klapic,
            APIC_LVT0,
            set_apic_delivery_mode(lvt_lint0, APIC_MODE_EXTINT),
        );
        let lvt_lint1 = get_klapic_reg(&klapic, APIC_LVT1);
        set_klapic_reg(
            &mut klapic,
            APIC_LVT1,
            set_apic_delivery_mode(lvt_lint1, APIC_MODE_NMI),
        );

        self.vcpu_fd.set_lapic(&klapic).map_err(Error::KvmIoctl)
    }

    /// vCPU emulation loop.
    #[allow(clippy::if_same_then_else)]
    pub fn run(&mut self, instruction_pointer: GuestAddress) -> Result<()> {
        if !self.running {
            self.configure_regs(instruction_pointer)?;
            self.running = true;
        }

        match self.vcpu_fd.run() {
            Ok(exit_reason) => {
                match exit_reason {
                    VcpuExit::Shutdown | VcpuExit::Hlt => {
                        println!("Guest shutdown: {:?}. Bye!", exit_reason);
                        if stdin().lock().set_canon_mode().is_err() {
                            eprintln!("Failed to set canon mode. Stdin will not echo.");
                        }
                        unsafe { libc::exit(0) };
                    }
                    VcpuExit::IoOut(addr, data) => {
                        if 0x3f8 <= addr && addr < (0x3f8 + 8) {
                            // Write at the serial port.
                            if self
                                .device_mgr
                                .lock()
                                .unwrap()
                                .pio_write(PioAddress(addr), data)
                                .is_err()
                            {
                                eprintln!("Failed to write to serial port");
                            }
                        } else if addr == 0x060 || addr == 0x061 || addr == 0x064 {
                            // Write at the i8042 port.
                            // See https://wiki.osdev.org/%228042%22_PS/2_Controller#PS.2F2_Controller_IO_Ports
                        } else if 0x070 <= addr && addr <= 0x07f {
                            // Write at the RTC port.
                        } else {
                            // Write at some other port.
                        }
                    }
                    VcpuExit::IoIn(addr, data) => {
                        if 0x3f8 <= addr && addr < (0x3f8 + 8) {
                            // Read from the serial port.
                            if self
                                .device_mgr
                                .lock()
                                .unwrap()
                                .pio_read(PioAddress(addr), data)
                                .is_err()
                            {
                                eprintln!("Failed to read from serial port");
                            }
                        } else {
                            // Read from some other port.
                        }
                    }
                    VcpuExit::MmioRead(addr, data) => {
                        if self
                            .device_mgr
                            .lock()
                            .unwrap()
                            .mmio_read(MmioAddress(addr), data)
                            .is_err()
                        {
                            eprintln!("Failed to read from mmio 0x{:x}", addr);
                        }
                    }
                    VcpuExit::MmioWrite(addr, data) => {
                        if self
                            .device_mgr
                            .lock()
                            .unwrap()
                            .mmio_write(MmioAddress(addr), data)
                            .is_err()
                        {
                            eprintln!("Failed to write to mmio 0x{:x}", addr);
                        }
                    }
                    VcpuExit::Xen(xen_exit) => {
                        trace!("VcpuExit::Xen");

                        match xen_exit {
                            XenExit::Hcall(hcall) => self.handle_xen_hcall(hcall),
                            XenExit::Unsupported(x) => panic!("Unsupported xen exit {}", x),
                        };
                    }
                    x => {
                        println!("Unhandled vcpu exit {:?}", x);
                    }
                }
            }
            Err(e) => eprintln!("Emulation error: {}", e),
        }
        Ok(())
    }

    fn handle_xen_hcall(&self, hcall: &mut kvm_xen_exit_hcall) {
        const HYPERVISOR_XEN_VERSION: u64 = 17;
        const HYPERVISOR_MEMORY_OP: u64 = 12;
        const HYPERVISOR_VCPU_OP: u64 = 24;
        const HYPERVISOR_EVENT_CHANNEL_OP: u64 = 32;
        const HYPERVISOR_HVM_OP: u64 = 34;

        const XENVER_GET_FEATURES: u64 = 6;
        const XENMEM_ADD_TO_PHYSMAP: u64 = 7;

        const VCPUOP_REGISTER_VCPU_INFO: u64 = 10;

        const HVMOP_SET_PARAM: u64 = 0;
        const HVMOP_GET_PARAM: u64 = 1;
        const HVMOP_PAGETABLE_DYING: u64 = 9;

        // The current code was written assuming `hcall.longmode` is always `1`.
        assert_eq!(hcall.longmode, 1);

        trace!("Xen hcall.input {}", hcall.input);

        let mut res = 0u64;

        match hcall.input {
            HYPERVISOR_XEN_VERSION => match hcall.params[0] {
                XENVER_GET_FEATURES => {
                    self.xen_get_features(hcall.params[1]);
                }
                _ => panic!("Unrecognized Xen version hcall op"),
            },
            HYPERVISOR_MEMORY_OP => match hcall.params[0] {
                XENMEM_ADD_TO_PHYSMAP => {
                    self.xen_add_to_physmap(hcall.params[1]);
                }
                _ => panic!("Unrecognized Xen memory hcall op"),
            },
            HYPERVISOR_HVM_OP => {
                trace!("Xen hvm op {}", hcall.params[0]);
                match hcall.params[0] {
                    HVMOP_SET_PARAM => {
                        trace!("Xen hvm op set param");
                        self.xen_set_param(hcall.params[1]);
                    }
                    HVMOP_GET_PARAM => {
                        trace!("Xen hvm op get param");
                        self.xen_get_param(hcall.params[1]);
                    }
                    HVMOP_PAGETABLE_DYING => {
                        trace!("Will return -ENOSYS for HVMOP_PAGETABLE_DYING");
                        res = (-libc::ENOSYS) as u64;
                    }
                    _ => panic!("Xen unrecognized hvm op"),
                }
            }
            HYPERVISOR_VCPU_OP => {
                trace!("Xen vcpu op {}", hcall.params[0]);
                match hcall.params[0] {
                    VCPUOP_REGISTER_VCPU_INFO => {
                        trace!(
                            "Xen REGISTER_VCPU_INFO {} 0x{:x}",
                            hcall.params[1],
                            hcall.params[2]
                        );
                        // TODO: do the actual registration logic here?
                    }
                    _ => panic!("Xen unrecognized vcpu op"),
                }
            }
            HYPERVISOR_EVENT_CHANNEL_OP => {
                trace!(
                    "xen event channel op {} 0x{:x}",
                    hcall.params[0],
                    hcall.params[1]
                );
                res = self.xen_evch_op(hcall.params[0], hcall.params[1]);
            }
            _ => panic!("Xen unrecognized hcall input"),
        }

        trace!("Xen hcall res {}", res);

        hcall.result = res;
    }

    fn xen_evch_op(&self, cmd: u64, _gva: u64) -> u64 {
        const EVTCHNOP_INIT_CONTROL: u64 = 11;

        match cmd {
            EVTCHNOP_INIT_CONTROL => (-libc::ENOSYS) as u64,
            // TODO: Actually handle other ops?
            _ => 0,
        }
    }

    fn xen_set_param(&self, gva: u64) {
        let mut param = xen_hvm_param::default();
        self.copy_from_gva(gva, &mut param);

        assert_eq!(param.domid, DOMID_SELF);

        const HVM_PARAM_CALLBACK_IRQ: u32 = 0;

        if param.index == HVM_PARAM_CALLBACK_IRQ {
            // TODO: Perform the actual setup.
            trace!("xen HVM_PARAM_CALLBACK_IRQ");
        }

        self.copy_to_gva(gva, &param);
    }

    fn xen_get_param(&self, gva: u64) {
        let mut param = xen_hvm_param::default();

        self.copy_from_gva(gva, &mut param);

        assert_eq!(param.domid, DOMID_SELF);

        const HVM_PARAM_STORE_PFN: u32 = 1;
        const HVM_PARAM_STORE_EVTCHN: u32 = 2;

        const XENSTORE_ADDR: u64 = 0xfffc0000 - 0x1000;
        const XENSTORE_PFN: u64 = XENSTORE_ADDR >> 12;
        const XENSTORE_EVTCHN: u64 = 1;

        param.value = match param.index {
            HVM_PARAM_STORE_PFN => XENSTORE_PFN,
            HVM_PARAM_STORE_EVTCHN => XENSTORE_EVTCHN,
            _ => 0,
        };

        self.copy_to_gva(gva, &param);
    }

    fn xen_add_to_physmap(&self, gva: u64) {
        const PAGE_SHIFT: u8 = 12;

        const XENMAPSPACE_SHARED_INFO: u32 = 0;
        const XENMAPSPACE_GRANT_TABLE: u32 = 1;

        #[derive(Default)]
        #[repr(C)]
        struct xen_add_to_physmap {
            domid: u16,
            size: u16,
            // unsigned int in C header
            space: u32,
            idx: u64,
            gpfn: u64,
        };

        let mut physmap = xen_add_to_physmap::default();

        self.copy_from_gva(gva, &mut physmap);

        // TODO: Return error (ESRCH) instead of panic here?
        assert_eq!(physmap.domid, DOMID_SELF);

        trace!("Xen physmap space {}", physmap.space);

        match physmap.space {
            XENMAPSPACE_SHARED_INFO => {
                // TODO: Return EINVAL instead of panic?
                assert_eq!(physmap.idx, 0);
                let gpa = physmap.gpfn << PAGE_SHIFT;
                self.xen_map_shared_info_page(gpa);
            }
            XENMAPSPACE_GRANT_TABLE => {
                trace!(
                    "XENMAPSPACE_GRANT_TABLE idx {} gpfn 0x{:x}",
                    physmap.idx,
                    physmap.gpfn
                );
                // TODO: Actually handle the operation?
            }
            x => panic!("Xen unexpected physmap.space value {}", x),
        }
    }

    fn xen_map_shared_info_page(&self, gpa: u64) {
        // Longmode is assumed to be == 1.
        const PAGE_SHIFT: u8 = 12;
        const PAGE_SIZE: usize = 1 << PAGE_SHIFT;

        assert_eq!(PAGE_SIZE, 0x1000);

        const KVM_XEN_ATTR_TYPE_SHARED_INFO: u16 = 0x1;
        const KVM_XEN_ATTR_TYPE_VCPU_INFO: u16 = 0x2;

        trace!("Xen shared info page gpa 0x{:x}", gpa);

        let new_shared_info = self.mem.get_slice(GuestAddress(gpa), PAGE_SIZE).unwrap();

        // Slowest initialization ever.
        for i in 0..PAGE_SIZE {
            new_shared_info.write_obj(0u8, i).unwrap();
        }

        let mut ha = kvm_xen_hvm_attr::default();
        ha.type_ = KVM_XEN_ATTR_TYPE_SHARED_INFO;
        ha.u.shared_info.gfn = gpa >> PAGE_SHIFT;
        self.vm_fd.xen_hvm_set_attr(&ha).unwrap();

        ha.type_ = KVM_XEN_ATTR_TYPE_VCPU_INFO;
        // This should've been done for each vcpu, but we assume there's a single vcpu for now.

        // Hardcoded vcpu_id.
        ha.u.vcpu_attr.vcpu_id = 0;
        ha.u.vcpu_attr.gpa = gpa;

        self.vm_fd.xen_hvm_set_attr(&ha).unwrap();
    }

    fn xen_get_features(&self, gva: u64) {
        #[derive(Default)]
        #[repr(C)]
        struct xen_feature_info {
            // Was `unsigned int` in the C code.
            submap_idx: u32, /* IN: which 32-bit submap to return */
            submap: u32,     /* OUT: 32-bit submap */
        };

        let mut info = xen_feature_info::default();

        self.copy_from_gva(gva, &mut info);
        trace!("Xen get features submap_idx {}", info.submap_idx);

        const XENFEAT_HVM_CALLBACK_VECTOR: u32 = 8;
        const XENFEAT_WRITABLE_PAGE_TABLES: u32 = 0;
        const XENFEAT_WRITABLE_DESCRIPTOR_TABLES: u32 = 1;
        const XENFEAT_AUTO_TRANSLATED_PHYSMAP: u32 = 2;
        const XENFEAT_SUPERVISOR_MODE_KERNEL: u32 = 3;

        info.submap = 0;
        if info.submap_idx == 0 {
            info.submap |= (1 << XENFEAT_HVM_CALLBACK_VECTOR)
                | (1 << XENFEAT_WRITABLE_PAGE_TABLES)
                | (1 << XENFEAT_WRITABLE_DESCRIPTOR_TABLES)
                | (1 << XENFEAT_AUTO_TRANSLATED_PHYSMAP)
                | (1 << XENFEAT_SUPERVISOR_MODE_KERNEL);
        }

        self.copy_to_gva(gva, &info);
    }

    pub fn copy_from_gva<T>(&self, gva: u64, obj: &mut T) {
        const PAGE_SIZE: u64 = 4096;

        let mut left = std::mem::size_of::<T>();

        // Hacky.
        let buf = unsafe { std::slice::from_raw_parts_mut(obj as *mut T as *mut u8, left) };

        let mut i = 0;
        while left > 0 {
            let mut t = kvm_translation {
                linear_address: gva + i as u64,
                ..Default::default()
            };

            let mut len = (PAGE_SIZE - (t.linear_address & (PAGE_SIZE - 1))) as usize;
            if len > left {
                len = left;
            }

            // Unwrap ...
            self.vcpu_fd.translate(&mut t).unwrap();

            // Unwrap ...
            self.mem
                .read_slice(&mut buf[i..i + len], GuestAddress(t.physical_address))
                .unwrap();

            i += len;
            left -= len;
        }
    }

    pub fn copy_to_gva<T>(&self, gva: u64, obj: &T) {
        const PAGE_SIZE: u64 = 4096;

        let mut left = std::mem::size_of::<T>();

        // Hacky.
        let buf = unsafe { std::slice::from_raw_parts(obj as *const T as *const u8, left) };

        let mut i = 0;
        while left > 0 {
            let mut t = kvm_translation {
                linear_address: gva + i as u64,
                ..Default::default()
            };

            let mut len = (PAGE_SIZE - (t.linear_address & (PAGE_SIZE - 1))) as usize;
            if len > left {
                len = left;
            }

            // Unwrap ...
            self.vcpu_fd.translate(&mut t).unwrap();

            // Unwrap ...
            self.mem
                .write_slice(&buf[i..i + len], GuestAddress(t.physical_address))
                .unwrap();

            i += len;
            left -= len;
        }
    }
}
