// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use std::cmp;
use std::io::{self, Read, Write};
use std::result;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use event_manager::{EventOps, Events, MutEventSubscriber};
use vm_memory::{Bytes, GuestAddressSpace};
use vm_virtio::{DescriptorChain, Queue};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use super::super::VIRTIO_MMIO_INT_VRING;
use super::tap::Tap;
use super::MAX_BUFFER_SIZE;

const TAPFD_DATA: u32 = 1;
const RXFD_DATA: u32 = 2;
const TXFD_DATA: u32 = 3;

enum Error {}

pub struct QueueHandler<M: GuestAddressSpace> {
    pub rxq: Queue<M>,
    pub rxfd: EventFd,
    pub rxbuf: [u8; MAX_BUFFER_SIZE],
    pub rxbuf_current: usize,
    pub txq: Queue<M>,
    pub txfd: EventFd,
    pub txbuf: [u8; MAX_BUFFER_SIZE],
    pub interrupt_status: Arc<AtomicU8>,
    pub irqfd: Arc<EventFd>,
    pub tap: Tap,
}

impl<M: GuestAddressSpace> QueueHandler<M> {
    fn signal_used_queue(&self) {
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING, Ordering::SeqCst);
        self.irqfd.write(1).expect("noooo");
    }

    fn write_frame_to_guest(&mut self) -> bool {
        let num_bytes = self.rxbuf_current;

        let mut chain = match self.rxq.iter().expect("nooo").next() {
            Some(c) => c,
            _ => return false,
        };

        let mut count = 0;
        let buf = &mut self.rxbuf[..num_bytes];

        while let Some(desc) = chain.next() {
            let left = buf.len() - count;

            if left == 0 {
                break;
            }

            let len = cmp::min(left, desc.len() as usize);
            chain
                .memory()
                .write_slice(&buf[count..count + len], desc.addr())
                .expect("nooo");

            count += len;
        }

        if count != buf.len() {
            // The buffer was too large for the chain.
            // Log something?
            println!("ASDF count != buf.len()");
        }

        self.rxq
            .add_used(chain.head_index(), count as u32)
            .expect("noooo");

        if self.rxq.needs_notification().expect("nooo") {
            self.signal_used_queue()
        }

        self.rxbuf_current = 0;

        true
    }

    fn process_tap(&mut self) {
        loop {
            if self.rxbuf_current == 0 {
                match self.tap.read(&mut self.rxbuf) {
                    Ok(n) => self.rxbuf_current = n,
                    Err(_) => {
                        // Do something (logs, metrics, etc.) in response to an error when reading
                        // from tap. EAGAIN means there's nothing available to read anymore (because
                        // we open the TAP as non-blocking).
                        break;
                    }
                }
            }

            if !self.write_frame_to_guest() {
                if !self.rxq.enable_notification().expect("noo") {
                    break;
                }
            }
        }
    }

    fn send_frame_from_chain(&mut self, chain: &mut DescriptorChain<M>) -> u32 {
        let mut count = 0;

        while let Some(desc) = chain.next() {
            let left = self.txbuf.len() - count;
            let len = desc.len() as usize;

            if len > left {
                panic!("asdf desc.len() > left");
            }

            chain
                .memory()
                .read_slice(&mut self.txbuf[count..count + len], desc.addr())
                .expect("no");

            count += len;
        }

        self.tap.write(&self.txbuf[..count]).expect("tap tap");

        count as u32
    }

    fn process_txq(&mut self) {
        loop {
            self.txq.disable_notification().expect("no");

            while let Some(mut chain) = self.txq.iter().expect("nooo").next() {
                let len = self.send_frame_from_chain(&mut chain);

                self.txq.add_used(chain.head_index(), len).expect("nooo");

                if self.txq.needs_notification().expect("nooo") {
                    self.signal_used_queue()
                }
            }

            if !self.txq.enable_notification().expect("no") {
                break;
            }
        }
    }

    fn process_rxq(&mut self) {
        self.rxq.disable_notification().expect("nonono");
        self.process_tap();
    }
}

impl<M: GuestAddressSpace> MutEventSubscriber for QueueHandler<M> {
    fn process(&mut self, events: Events, _ops: &mut EventOps) {
        if events.event_set() != EventSet::IN {
            panic!("unexpected event_set");
        }

        match events.data() {
            TAPFD_DATA => {
                // println!("ASDF PROCESS TAP");
                self.process_tap();
            }
            RXFD_DATA => {
                // println!("ASDF PROCESS RXFD");
                self.rxfd.read().expect("noo o o");
                self.process_rxq();
            }
            TXFD_DATA => {
                // println!("ASDF PROCESS TXFD");
                self.txfd.read().expect("noo o o");
                self.process_txq();
            }
            _ => panic!("unexpected data"),
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        ops.add(Events::with_data(
            &self.tap,
            TAPFD_DATA,
            EventSet::IN | EventSet::EDGE_TRIGGERED,
        ))
        .expect("Unable to add tapfd");

        ops.add(Events::with_data(&self.rxfd, RXFD_DATA, EventSet::IN))
            .expect("Unable to add rxfd");

        ops.add(Events::with_data(&self.txfd, TXFD_DATA, EventSet::IN))
            .expect("Unable to add txfd");
    }
}
