// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

pub mod block;
pub mod net;

const BLOCK_DEVICE_ID: u32 = 2;
const NET_DEVICE_ID: u32 = 1;

const VIRTIO_F_RING_EVENT_IDX: u64 = 1 << 29;
const VIRTIO_F_VERSION_1: u64 = 1 << 32;

const VIRTIO_MMIO_INT_VRING: u8 = 0x01;

// pub enum Error {
//
// }
