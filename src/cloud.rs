// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2016  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::net::{SocketAddr, ToSocketAddrs};
use std::collections::HashMap;
use std::hash::Hasher;
use std::net::UdpSocket;
use std::io::Read;
use std::io::Result as IoResult;
use std::fmt;
use std::marker::PhantomData;
use std::sync::{Arc, RwLock};
use std::thread;

use nix::sys::signal::{SIGTERM, SIGQUIT, SIGINT};
use signal::trap::Trap;
use time::{SteadyTime, self};
use rand::{random, sample, thread_rng};

use super::types::{Table, Protocol, Range, Error, NetworkId, NodeId};
use super::device::Device;
use super::udpmessage::{encode, decode, Options, Message};
use super::crypto::Crypto;
use super::util::{now, Time, Duration};

struct PeerList {
    timeout: Duration,
    peers: HashMap<SocketAddr, Time>
}

impl PeerList {
    fn new(timeout: Duration) -> PeerList {
        PeerList{peers: HashMap::new(), timeout: timeout}
    }

    fn timeout(&mut self) -> Vec<SocketAddr> {
        let now = now();
        let mut del: Vec<SocketAddr> = Vec::new();
        for (&addr, &timeout) in &self.peers {
            if timeout < now {
                del.push(addr);
            }
        }
        for addr in &del {
            debug!("Forgot peer: {}", addr);
            self.peers.remove(addr);
        }
        del
    }

    #[inline(always)]
    fn contains(&self, addr: &SocketAddr) -> bool {
        self.peers.contains_key(addr)
    }

    #[inline]
    fn add(&mut self, addr: &SocketAddr) {
        if self.peers.insert(*addr, now()+self.timeout as Time).is_none() {
            info!("New peer: {}", addr);
        }
    }

    #[inline]
    fn as_vec(&self) -> Vec<SocketAddr> {
        self.peers.keys().map(|addr| *addr).collect()
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.peers.len()
    }

    #[inline]
    fn subset(&self, size: usize) -> Vec<SocketAddr> {
        sample(&mut thread_rng(), self.as_vec(), size)
    }

    #[inline]
    fn remove(&mut self, addr: &SocketAddr) {
        if self.peers.remove(&addr).is_some() {
            info!("Removed peer: {}", addr);
        }
    }
}


pub struct Socket {
    options: Options,
    crypto: Crypto,
    socket: UdpSocket,
}

impl Socket {
    #[inline]
    pub fn new(options: Options, crypto: Crypto, socket: UdpSocket) -> Self {
        Socket{options: options, crypto: crypto, socket: socket}
    }

    #[inline]
    fn local_addr(&self) -> IoResult<SocketAddr> {
        self.socket.local_addr()
    }

    #[inline]
    fn broadcast_msg(&mut self, peers: &PeerList, msg: &mut Message, buffer: &mut [u8; 64*1024]) -> Result<(), Error> {
        debug!("Broadcasting {:?}", msg);
        let msg_data = encode(&mut self.options, msg, buffer, &mut self.crypto);
        for addr in peers.as_vec() {
            try!(match self.socket.send_to(msg_data, addr) {
                Ok(written) if written == msg_data.len() => Ok(()),
                Ok(_) => Err(Error::SocketError("Sent out truncated packet")),
                Err(e) => {
                    error!("Failed to send via network {:?}", e);
                    Err(Error::SocketError("IOError when sending"))
                }
            })
        }
        Ok(())
    }

    #[inline]
    fn send_msg(&mut self, addr: SocketAddr, msg: &mut Message, buffer: &mut [u8; 64*1024]) -> Result<(), Error> {
        debug!("Sending {:?} to {}", msg, addr);
        let msg_data = encode(&mut self.options, msg, buffer, &mut self.crypto);
        match self.socket.send_to(msg_data, addr) {
            Ok(written) if written == msg_data.len() => Ok(()),
            Ok(_) => Err(Error::SocketError("Sent out truncated packet")),
            Err(e) => {
                error!("Failed to send via network {:?}", e);
                Err(Error::SocketError("IOError when sending"))
            }
        }
    }

    #[inline]
    fn recv_from<'a>(&mut self, mut buffer: &'a mut [u8]) -> Result<(SocketAddr, Options, Message<'a>), Error> {
        let (size, src) = try!(self.socket.recv_from(&mut buffer).map_err(|_| Error::SocketError("Read error")));
        match decode(&mut buffer[..size], &mut self.crypto) {
            Ok((options, msg)) => Ok((src, options, msg)),
            Err(e) => Err(e)
        }
    }
}

impl Clone for Socket {
    fn clone(&self) -> Socket {
        Socket::new(self.options.clone(), self.crypto.clone(), self.socket.try_clone().expect("Failed to clone socket"))
    }
}


pub struct SocketListener<P: Protocol> {
    options: Options,
    learning: bool,
    socket: Socket,
    table: Arc<RwLock<Box<Table>>>,
    device_write: Device,
    node_id: NodeId,
    peers: Arc<RwLock<PeerList>>,
    addresses: Vec<Range>,
    blacklist_peers: Arc<RwLock<Vec<SocketAddr>>>,
    reconnect_peers: Arc<RwLock<Vec<SocketAddr>>>,
    buffer_out: [u8; 64*1024],
    _dummy_p: PhantomData<P>,
}

impl <P: Protocol> SocketListener<P> {
    pub fn connect<Addr: ToSocketAddrs+fmt::Display>(&mut self, addr: Addr, reconnect: bool) -> Result<(), Error> {
        if let Ok(mut addrs) = addr.to_socket_addrs() {
            while let Some(a) = addrs.next() {
                if self.peers.read().expect("Lock poisoned").contains(&a)
                    || self.blacklist_peers.read().expect("Lock poisoned").contains(&a) {
                    return Ok(());
                }
            }
        }
        debug!("Connecting to {}", addr);
        if reconnect {
            if let Ok(mut addrs) = addr.to_socket_addrs() {
                while let Some(a) = addrs.next() {
                    self.reconnect_peers.write().expect("Lock poisoned").push(a);
                }
            }
        }
        let subnets = self.addresses.clone();
        let node_id = self.node_id.clone();
        let mut msg = Message::Init(0, node_id, subnets);
        if let Ok(mut addrs) = addr.to_socket_addrs() {
            while let Some(a) = addrs.next() {
                //Ignore error this time
                self.socket.send_msg(a, &mut msg, &mut self.buffer_out).ok();
            }
        }
        Ok(())
    }

    pub fn handle_net_message(&mut self, peer: SocketAddr, options: Options, msg: Message) -> Result<(), Error> {
        if self.options.network_id != options.network_id {
            info!("Ignoring message from {} with wrong token {:?}", peer, options.network_id);
            return Err(Error::WrongNetwork(options.network_id));
        }
        debug!("Received {:?} from {}", msg, peer);
        match msg {
            Message::Data(payload, start, end) => {
                let (src, _dst) = try!(P::parse(&payload[start..end]));
                debug!("Writing data to device: {} bytes", end-start);
                match self.device_write.write(&payload[start..end]) {
                    Ok(()) => (),
                    Err(e) => {
                        error!("Failed to send via device: {}", e);
                        return Err(Error::TunTapDevError("Failed to write to device"));
                    }
                }
                // not adding peer to increase performance
                if self.learning {
                    //learn single address
                    self.table.write().expect("Lock poisoned").learn(src, None, peer);
                }
            },
            Message::Peers(peers) => {
                for p in &peers {
                    if ! self.peers.read().expect("Lock poisoned").contains(p)
                        && ! self.blacklist_peers.read().expect("Lock poisoned").contains(p) {
                        try!(self.connect(p, false));
                    }
                }
            },
            Message::Init(stage, node_id, ranges) => {
                if node_id == self.node_id {
                    self.blacklist_peers.write().expect("Lock poisoned").push(peer);
                    return Ok(())
                }
                self.peers.write().expect("Lock poisoned").add(&peer);
                let mut table = self.table.write().expect("Lock poisoned");
                for range in ranges {
                    table.learn(range.base, Some(range.prefix_len), peer.clone());
                }
                if stage == 0 {
                    let peers = self.peers.read().expect("Lock poisoned").as_vec();
                    let own_addrs = self.addresses.clone();
                    let own_node_id = self.node_id.clone();
                    try!(self.socket.send_msg(peer, &mut Message::Init(stage+1, own_node_id, own_addrs), &mut self.buffer_out));
                    try!(self.socket.send_msg(peer, &mut Message::Peers(peers), &mut self.buffer_out));
                }
            },
            Message::Close => {
                self.peers.write().expect("Lock poisoned").remove(&peer);
            }
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn run(&mut self) -> IoResult<()> {
        let mut buffer = [0; 64*1024];
        loop {
            match self.socket.recv_from(&mut buffer).and_then(|(src, options, msg)| self.handle_net_message(src, options, msg)) {
                Ok(_) => (),
                Err(e) => error!("Error: {}", e)
            }
        }
    }
}


pub struct DeviceListener<P: Protocol> {
    buffer_out: [u8; 64*1024],
    socket: Socket,
    device_read: Device,
    broadcast: bool,
    table: Arc<RwLock<Box<Table>>>,
    peers: Arc<RwLock<PeerList>>,
    _dummy_p: PhantomData<P>,
}

impl <P: Protocol> DeviceListener<P> {
    pub fn handle_interface_data(&mut self, payload: &mut [u8], start: usize, end: usize) -> Result<(), Error> {
        let (src, dst) = try!(P::parse(&payload[start..end]));
        debug!("Read data from interface: src: {}, dst: {}, {} bytes", src, dst, end-start);
        match self.table.read().expect("Lock poisoned").lookup(&dst) {
            Some(addr) => {
                debug!("Found destination for {} => {}", dst, addr);
                if self.peers.read().expect("Lock poisoned").contains(&addr) {
                    try!(self.socket.send_msg(addr, &mut Message::Data(payload, start, end), &mut self.buffer_out))
                } else {
                    warn!("Destination for {} not found in peers: {}", dst, addr);
                }
            },
            None => {
                if !self.broadcast {
                    debug!("No destination for {} found, dropping", dst);
                    return Ok(());
                }
                debug!("No destination for {} found, broadcasting", dst);
                let mut msg = Message::Data(payload, start, end);
                try!(self.socket.broadcast_msg(&self.peers.read().expect("Lock poisoned"), &mut msg, &mut self.buffer_out));
            }
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn run(&mut self) -> IoResult<()> {
        let mut buffer = [0; 64*1024];
        loop {
            let start = 64;
            let size = try_fail!(self.device_read.read(&mut buffer[start..]), "Failed to read from tap device: {}");
            match self.handle_interface_data(&mut buffer, start, start+size) {
                Ok(_) => (),
                Err(e) => error!("Error: {}", e)
            }
        }
    }
}


pub struct Housekeeper<P: Protocol> {
    addresses: Vec<Range>,
    blacklist_peers: Arc<RwLock<Vec<SocketAddr>>>,
    node_id: NodeId,
    buffer_out: [u8; 64*1024],
    socket: Socket,
    table: Arc<RwLock<Box<Table>>>,
    peers: Arc<RwLock<PeerList>>,
    next_peerlist: Time,
    update_freq: Duration,
    reconnect_peers: Arc<RwLock<Vec<SocketAddr>>>,
    _dummy_p: PhantomData<P>,
}

impl <P: Protocol> Housekeeper<P> {
    pub fn connect<Addr: ToSocketAddrs+fmt::Display>(&mut self, addr: Addr, reconnect: bool) -> Result<(), Error> {
        if let Ok(mut addrs) = addr.to_socket_addrs() {
            while let Some(a) = addrs.next() {
                if self.peers.read().expect("Lock poisoned").contains(&a)
                    || self.blacklist_peers.read().expect("Lock poisoned").contains(&a) {
                    return Ok(());
                }
            }
        }
        debug!("Connecting to {}", addr);
        if reconnect {
            if let Ok(mut addrs) = addr.to_socket_addrs() {
                while let Some(a) = addrs.next() {
                    self.reconnect_peers.write().expect("Lock poisoned").push(a);
                }
            }
        }
        let subnets = self.addresses.clone();
        let node_id = self.node_id.clone();
        let mut msg = Message::Init(0, node_id, subnets);
        if let Ok(mut addrs) = addr.to_socket_addrs() {
            while let Some(a) = addrs.next() {
                //Ignore error this time
                self.socket.send_msg(a, &mut msg, &mut self.buffer_out).ok();
            }
        }
        Ok(())
    }

    fn housekeep(&mut self) -> Result<(), Error> {
        self.peers.write().expect("Lock poisoned").timeout();
        self.table.write().expect("Lock poisoend").housekeep();
        if self.next_peerlist <= now() {
            debug!("Send peer list to all peers");
            let peers = self.peers.read().expect("Lock poisoend");
            let mut peer_num = peers.len();
            if peer_num > 10 {
                peer_num = (peer_num as f32).sqrt().ceil() as usize;
                if peer_num < 10 {
                    peer_num = 10;
                }
                if peer_num > 255 {
                    peer_num = 255
                }
            }
            let mut msg = Message::Peers(peers.subset(peer_num));
            try!(self.socket.broadcast_msg(&peers, &mut msg, &mut self.buffer_out));
            self.next_peerlist = now() + self.update_freq as Time;
        }
        let peers = self.reconnect_peers.read().expect("Lock poisoned").clone();
        for addr in peers.iter() {
            try!(self.connect(addr, false));
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn run(&mut self) -> IoResult<()> {
        let trap = Trap::trap(&[SIGINT, SIGTERM, SIGQUIT]);
        loop {
            let timeout = SteadyTime::now() + time::Duration::seconds(1);
            // Check for signals
            if trap.wait(timeout).is_some() {
                break;
            }
            // Do the housekeeping
            match self.housekeep() {
                Ok(_) => (),
                Err(e) => error!("Error: {}", e)
            }
        }
        info!("Shutting down...");
        self.socket.broadcast_msg(&self.peers.read().expect("Lock poisoned"), &mut Message::Close, &mut self.buffer_out).ok();
        Ok(())
    }
}


pub struct GenericCloud<P: Protocol> {
    socket_listener: SocketListener<P>,
    device_listener: DeviceListener<P>,
    housekeeper: Housekeeper<P>
}

impl<P: Protocol + 'static> GenericCloud<P> {
    pub fn new(device: Device, listen: &str, network_id: Option<NetworkId>, table: Box<Table>,
            peer_timeout: Duration, learning: bool, broadcast: bool, addresses: Vec<Range>,
            crypto: Crypto) -> Self {
        let socket = match UdpSocket::bind(listen) {
            Ok(socket) => socket,
            _ => fail!("Failed to open socket {}", listen)
        };
        let mut options = Options::default();
        options.network_id = network_id;
        let socket = Socket::new(options.clone(), crypto, socket);
        let node_id = random();
        let table = Arc::new(RwLock::new(table));
        let peers = Arc::new(RwLock::new(PeerList::new(peer_timeout)));
        let reconnect_peers = Arc::new(RwLock::new(Vec::new()));
        let blacklist_peers = Arc::new(RwLock::new(Vec::new()));
        let socket_listener = SocketListener{
            options: options,
            learning: learning,
            socket: socket.clone(),
            addresses: addresses.clone(),
            device_write: device.clone(),
            table: table.clone(),
            peers: peers.clone(),
            node_id: node_id,
            reconnect_peers: reconnect_peers.clone(),
            blacklist_peers: blacklist_peers.clone(),
            buffer_out: [0; 64*1024],
            _dummy_p: PhantomData
        };
        let device_listener = DeviceListener{
            device_read: device,
            broadcast: broadcast,
            table: table.clone(),
            peers: peers.clone(),
            socket: socket.clone(),
            buffer_out: [0; 64*1024],
            _dummy_p: PhantomData
        };
        let housekeeper = Housekeeper{
            addresses: addresses,
            blacklist_peers: blacklist_peers.clone(),
            node_id: node_id,
            table: table.clone(),
            peers: peers.clone(),
            socket: socket.clone(),
            reconnect_peers: reconnect_peers.clone(),
            next_peerlist: now(),
            update_freq: peer_timeout/2,
            buffer_out: [0; 64*1024],
            _dummy_p: PhantomData
        };
        GenericCloud{
            socket_listener: socket_listener,
            device_listener: device_listener,
            housekeeper: housekeeper
        }
    }

    pub fn connect<Addr: ToSocketAddrs+fmt::Display>(&mut self, addr: Addr, reconnect: bool) -> Result<(), Error> {
        self.socket_listener.connect(addr, reconnect)
    }

    #[inline]
    pub fn ifname(&self) -> &str {
        self.device_listener.device_read.ifname()
    }

    #[allow(dead_code)]
    pub fn address(&self) -> IoResult<SocketAddr> {
        self.socket_listener.socket.local_addr()
    }

    #[allow(dead_code)]
    pub fn peer_count(&self) -> usize {
        self.socket_listener.peers.read().expect("Lock poisoned").len()
    }

    pub fn run(self) {
        let mut socket_listener = self.socket_listener;
        thread::spawn(move || socket_listener.run());
        let mut device_listener = self.device_listener;
        thread::spawn(move || device_listener.run());
        let mut housekeeper = self.housekeeper;
        let _ = housekeeper.run();
    }
}
