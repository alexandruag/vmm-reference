use std::sync::atomic::AtomicU8;
use std::sync::Arc;

use vm_device::bus::MmioAddress;
use vm_device::MutDeviceMmio;
use vm_memory::GuestAddressSpace;
use vm_virtio::device::{VirtioConfig, VirtioMmioDevice, WithVirtioConfig};
use vm_virtio::Queue;

const BLOCK_DEVICE_ID: u32 = 2;

pub struct Block<M: GuestAddressSpace> {
    cfg: VirtioConfig<M>,
}

impl<M: GuestAddressSpace + Clone> Block<M> {
    pub fn new(mem: M) -> Self {
        // TODO: populate features (at least the version_1 feature)!
        let device_features = 0;
        let queue_max_size = 128;

        // TODO: populate config space?

        let cfg = VirtioConfig {
            device_features,
            driver_features: 0,
            device_features_select: 0,
            driver_features_select: 0,
            device_status: 0,
            queue_select: 0,
            queues: vec![Queue::new(mem.clone(), queue_max_size)],
            config_generation: 0,
            config_space: Vec::new(),
            device_activated: false,
            interrupt_status: Arc::new(AtomicU8::new(0)),
        };

        Block { cfg }
    }
}

impl<M: GuestAddressSpace> WithVirtioConfig<M> for Block<M> {
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
        panic!("IM ACTIVATING")
    }

    fn reset(&mut self) {
        // Add device-specific reset logic here (or do something simple if we don't intend to
        // support reset functionality for this device).
    }
}

// At this point, `SomeDevice` implements `VirtioDevice` and `VirtioMmioDevice` due to the
// automatic implementations enabled by `WithVirtioConfig`.

// Since `SomeDevice` implements `VirtioMmioDevice`, we can easily add a MMIO bus device
// implementation to it as well. We need to do this explicitly, instead of automatically
// implementing `MutDeviceMmio` like for the other traits, because we're no longer working
// with a trait that's defined as part of the same crate.

// Adding a `static bound to simplify lifetime handling.
impl<M: GuestAddressSpace + 'static> MutDeviceMmio for Block<M> {
    fn mmio_read(&mut self, _base: MmioAddress, offset: u64, data: &mut [u8]) {
        self.read(offset, data)
    }

    fn mmio_write(&mut self, _base: MmioAddress, offset: u64, data: &[u8]) {
        self.write(offset, data)
    }
}
