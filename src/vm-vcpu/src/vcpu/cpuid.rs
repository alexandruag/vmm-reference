// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use kvm_bindings::CpuId;
use kvm_ioctls::{Cap::TscDeadlineTimer, Kvm};

// CPUID bits in ebx, ecx, and edx.
const EBX_CLFLUSH_CACHELINE: u32 = 8; // Flush a cache line size.
const EBX_CLFLUSH_SIZE_SHIFT: u32 = 8; // Bytes flushed when executing CLFLUSH.
const EBX_CPU_COUNT_SHIFT: u32 = 16; // Index of this CPU.
const EBX_CPUID_SHIFT: u32 = 24; // Index of this CPU.
const ECX_EPB_SHIFT: u32 = 3; // "Energy Performance Bias" bit.
const ECX_TSC_DEADLINE_TIMER_SHIFT: u32 = 24; // TSC deadline mode of APIC timer
const ECX_HYPERVISOR_SHIFT: u32 = 31; // Flag to be set when the cpu is running on a hypervisor.
const EDX_HTT_SHIFT: u32 = 28; // Hyper Threading Enabled.

const XEN_CPUID_BASE: u32 = 0x4000_0000;

const XEN_CPUID_SIGNATURE_IDX: u32 = 0;
const XEN_CPUID_VERSION_IDX: u32 = 1;
const XEN_CPUID_MSR_BASE_IDX: u32 = 2;

const XEN_PVHVM_MSR_BASE: u32 = 0x800_0000;

pub fn filter_cpuid(kvm: &Kvm, vcpu_id: usize, cpu_count: usize, cpuid: &mut CpuId) {
    let mut xen_base_filtered = false;
    let mut xen_version_filtered = false;

    for entry in cpuid.as_mut_slice().iter_mut() {
        match entry.function {
            1 => {
                // X86 hypervisor feature.
                if entry.index == 0 {
                    entry.ecx |= 1 << ECX_HYPERVISOR_SHIFT;
                }
                if kvm.check_extension(TscDeadlineTimer) {
                    entry.ecx |= 1 << ECX_TSC_DEADLINE_TIMER_SHIFT;
                }
                entry.ebx = (vcpu_id << EBX_CPUID_SHIFT) as u32
                    | (EBX_CLFLUSH_CACHELINE << EBX_CLFLUSH_SIZE_SHIFT);
                if cpu_count > 1 {
                    entry.ebx |= (cpu_count as u32) << EBX_CPU_COUNT_SHIFT;
                    entry.edx |= 1 << EDX_HTT_SHIFT;
                }
            }
            6 => {
                // Clear X86 EPB feature. No frequency selection in the hypervisor.
                entry.ecx &= !(1 << ECX_EPB_SHIFT);
            }
            11 => {
                // EDX bits 31..0 contain x2APIC ID of current logical processor.
                entry.edx = vcpu_id as u32;
            }
            x if x == XEN_CPUID_BASE + XEN_CPUID_SIGNATURE_IDX => {
                entry.eax = XEN_CPUID_BASE + XEN_CPUID_MSR_BASE_IDX;
                entry.ebx = u32::from_le_bytes(*b"XenV");
                entry.ecx = u32::from_le_bytes(*b"MMXe");
                entry.edx = u32::from_le_bytes(*b"nVMM");

                xen_base_filtered = true;
            }
            x if x == XEN_CPUID_BASE + XEN_CPUID_VERSION_IDX => {
                entry.index = 0;

                // Pretend we're Xen 4.11.
                // entry.eax = (4u32 << 16) | 11u32;

                // Pretend we're Xen 3.4.
                entry.eax = (3u32 << 16) | 4u32;

                xen_version_filtered = true;
            }
            x if x == XEN_CPUID_BASE + XEN_CPUID_MSR_BASE_IDX => {
                // This leaf is not supposed to be part of the default set that's getting
                // filtered. We're adding it manually below.
                unreachable!()
            }
            _ => (),
        }
    }

    // We currently rely on these being present and processed above.
    assert!(xen_base_filtered);
    assert!(xen_version_filtered);

    // Explicitly add this leaf to the cpuid entry set.
    let mut y = kvm_bindings::kvm_cpuid_entry2::default();
    y.function = XEN_CPUID_BASE + XEN_CPUID_MSR_BASE_IDX;
    y.index = 0;
    y.eax = 1;
    y.ebx = XEN_PVHVM_MSR_BASE;
    cpuid
        .push(y)
        .expect("Insufficient capacity for additional leaf");
}
