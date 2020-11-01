// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

mod request;

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use event_manager::{
    EventOps, Events, MutEventSubscriber, RemoteEndpoint, Result as EvmgrResult, SubscriberId,
};
use kvm_ioctls::{IoEventAddress, VmFd};
use vm_device::bus::MmioAddress;
use vm_device::MutDeviceMmio;
use vm_memory::{Bytes, GuestAddressSpace};
use vm_virtio::device::{VirtioConfig, VirtioMmioDevice, WithVirtioConfig};
use vm_virtio::Queue;
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

use super::{BLOCK_DEVICE_ID, VIRTIO_F_VERSION_1, VIRTIO_MMIO_INT_VRING};

use self::request::{DiskProperties, Request};

const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;

const SECTOR_SHIFT: u8 = 9;
const SECTOR_SIZE: u64 = (0x01 as u64) << SECTOR_SHIFT;

pub struct Block<M: GuestAddressSpace> {
    cfg: VirtioConfig<M>,
    endpoint: RemoteEndpoint<Box<dyn MutEventSubscriber + Send>>,
    vm_fd: Arc<VmFd>,
    irqfd: Arc<EventFd>,
}

impl<M: GuestAddressSpace + Clone> Block<M> {
    pub fn new(
        mem: M,
        endpoint: RemoteEndpoint<Box<dyn MutEventSubscriber + Send>>,
        vm_fd: Arc<VmFd>,
    ) -> Self {
        // TODO: populate features (at least the version_1 feature)!
        let device_features = VIRTIO_F_VERSION_1 | VIRTIO_BLK_F_FLUSH;
        // TODO: make configurable
        let queue_max_size = 256;

        let config_space = DiskProperties::new("disk.ext4".to_owned(), false)
            .expect("nooo")
            .virtio_block_config_space();

        // TODO: populate config space?

        let cfg = VirtioConfig {
            device_features,
            driver_features: 0,
            device_features_select: 0,
            driver_features_select: 0,
            device_status: 0,
            queue_select: 0,
            // A block device has a single queue.
            queues: vec![Queue::new(mem.clone(), queue_max_size)],
            config_generation: 0,
            // Empty config space for now.
            config_space,
            device_activated: false,
            interrupt_status: Arc::new(AtomicU8::new(0)),
        };

        let irqfd = EventFd::new(EFD_NONBLOCK).expect("noooo");
        // hardcoded 5;
        vm_fd.register_irqfd(&irqfd, 5).expect("boooooo");

        Block {
            cfg,
            endpoint,
            vm_fd,
            irqfd: Arc::new(irqfd),
        }
    }
}

impl<M: GuestAddressSpace + Clone + Send + 'static> WithVirtioConfig<M> for Block<M> {
    fn device_type(&self) -> u32 {
        BLOCK_DEVICE_ID
    }

    fn virtio_config(&self) -> &VirtioConfig<M> {
        &self.cfg
    }

    fn virtio_config_mut(&mut self) -> &mut VirtioConfig<M> {
        &mut self.cfg
    }

    fn activate(&mut self) {
        println!("IM ACTIVATING");
        let ioeventfd = EventFd::new(EFD_NONBLOCK).expect("nooooo");
        // hardcody; register ioeventfds
        self.vm_fd
            .register_ioevent(
                &ioeventfd,
                // super super hard-coded
                &IoEventAddress::Mmio(super::super::super::MMIO_MEM_START + 0x50),
                0u32,
            )
            .expect("nooo");

        // Hardcoded for now.
        let disk = DiskProperties::new("disk.ext4".to_owned(), false).expect("nooo");

        let handler = QueueHandler {
            queue: self.cfg.queues[0].clone(),
            interrupt_status: self.cfg.interrupt_status.clone(),
            irqfd: self.irqfd.clone(),
            ioeventfd,
            disk,
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

    // fn queue_notify(&mut self, hmm: u32) {
    //     panic!("queue notify {}", hmm);
    // }
}

// At this point, `Block` implements `VirtioDevice` and `VirtioMmioDevice` due to the
// automatic implementations enabled by `WithVirtioConfig`.

// Since `SomeDevice` implements `VirtioMmioDevice`, we can easily add a MMIO bus device
// implementation to it as well. We need to do this explicitly, instead of automatically
// implementing `MutDeviceMmio` like for the other traits, because we're no longer working
// with a trait that's defined as part of the same crate.

// Adding a `static bound to simplify lifetime handling.
impl<M: GuestAddressSpace + Clone + Send + 'static> MutDeviceMmio for Block<M> {
    fn mmio_read(&mut self, _base: MmioAddress, offset: u64, data: &mut [u8]) {
        self.read(offset, data);
    }

    fn mmio_write(&mut self, _base: MmioAddress, offset: u64, data: &[u8]) {
        self.write(offset, data);
    }
}

const IOEVENTFD_DATA: u32 = 1;

struct QueueHandler<M: GuestAddressSpace> {
    queue: Queue<M>,
    interrupt_status: Arc<AtomicU8>,
    irqfd: Arc<EventFd>,
    ioeventfd: EventFd,
    disk: DiskProperties,
}

impl<M: GuestAddressSpace> QueueHandler<M> {
    fn signal_used_queue(&self) {
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING, Ordering::SeqCst);
        self.irqfd.write(1).expect("noooo");
    }
}

impl<M: GuestAddressSpace> MutEventSubscriber for QueueHandler<M> {
    fn process(&mut self, events: Events, _ops: &mut EventOps) {
        if events.event_set() != EventSet::IN {
            panic!("unexpected event_set");
        }

        if events.data() != IOEVENTFD_DATA {
            panic!("unexpected events data {}", events.data());
        }

        if self.ioeventfd.read().is_err() {
            // TODO: Do something?
        }

        loop {
            self.queue.disable_notification().expect("noooo");

            while let Some(mut chain) = self.queue.iter().expect("nooo").next() {
                let len;

                if let Ok(request) = Request::parse(&mut chain) {
                    let status = match request.execute(&mut self.disk, chain.memory()) {
                        Ok(l) => {
                            len = l;
                            // VIRTIO_BLK_S_OK
                            0
                        }
                        Err(e) => {
                            println!("ASDF Failed to execute request: {:?}", e);
                            len = 1;
                            e.status()
                        }
                    };
                    // TODO: The executor can actually write the status itself, right?
                    chain
                        .memory()
                        .write_obj(status, request.status_addr)
                        .unwrap();

                    self.queue.add_used(chain.head_index(), len).expect("nooo");

                    if self.queue.needs_notification().expect("nooo") {
                        self.signal_used_queue()
                    }
                } else {
                    panic!("request parse chain error");
                }
            }

            if !self.queue.enable_notification().expect("noo") {
                break;
            }
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        ops.add(Events::with_data(
            &self.ioeventfd,
            IOEVENTFD_DATA,
            EventSet::IN,
        ))
        .expect("nooo");
    }
}
