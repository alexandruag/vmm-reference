// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

mod bindings;
mod handler;
mod tap;

use std::sync::atomic::AtomicU8;
use std::sync::Arc;

use event_manager::{MutEventSubscriber, RemoteEndpoint, Result as EvmgrResult, SubscriberId};
use kvm_ioctls::{IoEventAddress, VmFd};
use vm_device::bus::MmioAddress;
use vm_device::MutDeviceMmio;
use vm_memory::GuestAddressSpace;
use vm_virtio::device::{VirtioConfig, VirtioMmioDevice, WithVirtioConfig};
use vm_virtio::Queue;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

use handler::QueueHandler;
use tap::Tap;

use super::{NET_DEVICE_ID, VIRTIO_F_RING_EVENT_IDX, VIRTIO_F_VERSION_1, VIRTIO_MMIO_INT_VRING};

// Valued taken from the virtio standard.
const VIRTIO_NET_F_CSUM: u64 = 1 << 0;
const VIRTIO_NET_F_GUEST_CSUM: u64 = 1 << 1;
const VIRTIO_NET_F_GUEST_TSO4: u64 = 1 << 7;
const VIRTIO_NET_F_GUEST_UFO: u64 = 1 << 10;
const VIRTIO_NET_F_HOST_TSO4: u64 = 1 << 11;
const VIRTIO_NET_F_HOST_UFO: u64 = 1 << 14;

const MAX_BUFFER_SIZE: usize = 65562;

pub struct Net<M: GuestAddressSpace> {
    cfg: VirtioConfig<M>,
    endpoint: RemoteEndpoint<Box<dyn MutEventSubscriber + Send>>,
    vm_fd: Arc<VmFd>,
    irqfd: Arc<EventFd>,
    tap_name: String,
}

impl<M: GuestAddressSpace + Clone + Send + 'static> Net<M> {
    pub fn new(
        mem: M,
        endpoint: RemoteEndpoint<Box<dyn MutEventSubscriber + Send>>,
        vm_fd: Arc<VmFd>,
    ) -> Self {
        // TODO: populate features (at least the version_1 feature)!
        // What other features to support?
        let device_features = VIRTIO_F_VERSION_1
            | VIRTIO_NET_F_CSUM
            | VIRTIO_NET_F_GUEST_CSUM
            | VIRTIO_NET_F_GUEST_TSO4
            | VIRTIO_NET_F_GUEST_UFO
            | VIRTIO_NET_F_HOST_TSO4
            | VIRTIO_NET_F_HOST_UFO
            | VIRTIO_F_RING_EVENT_IDX;

        // hardcoded
        let tap_name = "vmtap35".to_owned();

        // TODO: make configurable
        let queue_max_size = 256;

        // TODO: populate config space?

        // A net device has (at least) two queues.
        let mut queues = vec![Queue::new(mem.clone(), queue_max_size); 2];
        for q in queues.iter_mut() {
            // We assumed the driver actually acknowledged this :D
            q.set_event_idx(true);
        }

        let cfg = VirtioConfig {
            device_features,
            driver_features: 0,
            device_features_select: 0,
            driver_features_select: 0,
            device_status: 0,
            queue_select: 0,
            queues,
            config_generation: 0,
            // Empty config space for now.
            config_space: Vec::new(),
            device_activated: false,
            interrupt_status: Arc::new(AtomicU8::new(0)),
        };

        let irqfd = EventFd::new(EFD_NONBLOCK).expect("noooo");
        // !!!! hardcoded 6 !!!!
        vm_fd.register_irqfd(&irqfd, 6).expect("boooooo");

        Net {
            cfg,
            endpoint,
            vm_fd,
            irqfd: Arc::new(irqfd),
            tap_name,
        }
    }
}

impl<M: GuestAddressSpace + Clone + Send + 'static> WithVirtioConfig<M> for Net<M> {
    fn device_type(&self) -> u32 {
        NET_DEVICE_ID
    }

    fn virtio_config(&self) -> &VirtioConfig<M> {
        &self.cfg
    }

    fn virtio_config_mut(&mut self) -> &mut VirtioConfig<M> {
        &mut self.cfg
    }

    fn activate(&mut self) {
        println!("IM ALSO ACTIVATING");
        let rxfd = EventFd::new(EFD_NONBLOCK).expect("nooooo");
        let txfd = EventFd::new(EFD_NONBLOCK).expect("nooooo");

        // hardcody; register ioeventfds
        self.vm_fd
            .register_ioevent(
                &rxfd,
                // super super hard-coded
                &IoEventAddress::Mmio(super::super::super::MMIO_MEM_START + 0x1000 + 0x50),
                0u32,
            )
            .expect("nooo");

        self.vm_fd
            .register_ioevent(
                &txfd,
                // super super hard-coded
                &IoEventAddress::Mmio(super::super::super::MMIO_MEM_START + 0x1000 + 0x50),
                1u32,
            )
            .expect("nooo");

        let mut rxq = self.cfg.queues[0].clone();
        // We're currently not making use of driver notifications for the rxq.
        // rxq.disable_notification().expect("nooo");

        let txq = self.cfg.queues[1].clone();

        // Hardcoded for now.
        let tap = Tap::open_named(self.tap_name.as_str()).expect("noooo");

        // Set offload flags to match the relevant virtio features of the device (for now,
        // statically set in the constructor.
        tap.set_offload(
            bindings::TUN_F_CSUM
                | bindings::TUN_F_UFO
                | bindings::TUN_F_TSO4
                | bindings::TUN_F_TSO6,
        )
        .expect("nooo ooo ooo");

        // The layout of the header is specified in the standard and is 12 bytes in size. We
        // should define this somewhere.
        tap.set_vnet_hdr_size(12).expect("zzzz");

        let handler = QueueHandler {
            rxq,
            rxfd,
            rxbuf: [0u8; MAX_BUFFER_SIZE],
            rxbuf_current: 0,
            txq,
            txfd,
            txbuf: [0u8; MAX_BUFFER_SIZE],
            interrupt_status: self.cfg.interrupt_status.clone(),
            irqfd: self.irqfd.clone(),
            tap,
        };

        // We can keep the _sub_id here for further interaction.
        let _sub_id = self
            .endpoint
            .call_blocking(move |mgr| -> EvmgrResult<SubscriberId> {
                Ok(mgr.add_subscriber(Box::new(handler)))
            })
            .expect("nooo");

        self.cfg.device_activated = true;
    }

    fn reset(&mut self) {
        // Not implemented for now.
    }
}

// At this point, `Net` implements `VirtioDevice` and `VirtioMmioDevice` due to the
// automatic implementations enabled by `WithVirtioConfig`.

// Adding a `static bound to simplify lifetime handling.
impl<M: GuestAddressSpace + Clone + Send + 'static> MutDeviceMmio for Net<M> {
    fn mmio_read(&mut self, _base: MmioAddress, offset: u64, data: &mut [u8]) {
        self.read(offset, data);
    }

    fn mmio_write(&mut self, _base: MmioAddress, offset: u64, data: &[u8]) {
        self.write(offset, data);
    }
}
