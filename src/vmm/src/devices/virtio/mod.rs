pub mod block;
pub mod net;

const VIRTIO_F_VERSION_1: u64 = 1 << 32;
const VIRTIO_MMIO_INT_VRING: u8 = 0x01;
