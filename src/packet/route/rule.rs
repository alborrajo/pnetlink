//! Rules operations
use packet::route::{FibRulePacket,MutableIfInfoPacket,RtAttrIterator};
use packet::route::link::Link;
use packet::route::route;
use packet::netlink::{MutableNetlinkPacket,NetlinkPacket,NetlinkErrorPacket};
use packet::netlink::NetlinkMsgFlags;
use packet::netlink::{NetlinkBufIterator,NetlinkReader,NetlinkRequestBuilder};
use socket::{NetlinkSocket,NetlinkProtocol};
use packet::netlink::NetlinkConnection;
use pnet::packet::MutablePacket;
use pnet::packet::Packet;
use pnet::packet::PacketSize;
use pnet::util::MacAddr;
use libc;

use std::net::Ipv4Addr;
use std::io::{Read,Write,Cursor,self};
use byteorder::{LittleEndian, BigEndian, ReadBytesExt};

pub const RTM_NEWRULE: u16 = 32;
pub const RTM_DELRULE: u16 = 33;
pub const RTM_GETRULE: u16 = 34;

pub const FRA_UNSPEC: u16 = 0;
pub const FRA_DST: u16 = 1;        /* destination address */
pub const FRA_SRC: u16 = 2;        /* source address */
pub const FRA_IFNAME: u16 = 3;    /* interface name */
pub const FRA_GOTO: u16 = 4;       /* target to jump to (FR_ACT_GOTO) */
pub const FRA_UNUSED2: u16 = 5;
pub const FRA_PRIORITY: u16 = 6;   /* priority/preference */
pub const FRA_UNUSED3: u16 = 7;
pub const FRA_UNUSED4: u16 = 8;
pub const FRA_UNUSED5: u16 = 9;
pub const FRA_FWMARK: u16 = 10;     /* mark */
pub const FRA_FLOW: u16 = 11;       /* flow/class id */
pub const FRA_TUN_ID: u16 = 12;
pub const FRA_SUPPRESS_IFGROUP: u16 = 13;
pub const FRA_SUPPRESS_PREFIXLEN: u16 = 14;
pub const FRA_TABLE: u16 = 15;      /* Extended table id */
pub const FRA_FWMASK: u16 = 16;     /* mask for netfilter mark */
pub const FRA_OIFNAME: u16 = 17;
pub const FRA_PAD: u16 = 18;
pub const FRA_L3MDEV: u16 = 19;
pub const FRA_UID_RANGE: u16 = 20;
pub const FRA_PROTOCOL: u16 = 21;  
pub const FRA_IP_PROTO: u16 = 22;
pub const FRA_SPORT_RANGE: u16 = 23;
pub const FRA_DPORT_RANGE: u16 = 24;
pub const __FRA_MAX: u16 = 25;



pub trait Rules where Self: Read + Write {
    fn iter_rules<'a>(&'a mut self) -> io::Result<Box<Iterator<Item = Rule> +'a>>;
    fn get_table_rules<'a>(&'a mut self, table_id: u8) -> io::Result<Box<Iterator<Item = Rule> +'a>>;
}

impl Rules for NetlinkConnection {
    /// iterate over rules
    fn iter_rules<'a>(&'a mut self) -> io::Result<Box<Iterator<Item = Rule> +'a>> {
        let mut buf = vec![0; MutableIfInfoPacket::minimum_packet_size()];
        let req = NetlinkRequestBuilder::new(RTM_GETRULE, NetlinkMsgFlags::NLM_F_DUMP)
            .append({
                let mut ifinfo = MutableIfInfoPacket::new(&mut buf).unwrap();
                ifinfo.set_family(0 /* AF_UNSPEC */);
                ifinfo
            }).build();
        let mut reply = self.send(req);
        let iter = RulesIterator { iter: reply.into_iter() };
        Ok(Box::new(iter))
    }

    /// iterate over rules
    fn get_table_rules<'a>(&'a mut self, table_id: u8) -> io::Result<Box<Iterator<Item = Rule> +'a>> {
        let mut buf = vec![0; MutableIfInfoPacket::minimum_packet_size()];
        let req = NetlinkRequestBuilder::new(RTM_GETRULE, NetlinkMsgFlags::NLM_F_DUMP)
            .append({
                let mut ifinfo = MutableIfInfoPacket::new(&mut buf).unwrap();
                ifinfo.set_family(0 /* AF_UNSPEC */);
                ifinfo
            }).build();
        let mut reply = self.send(req);
        let iter = RulesIterator { iter: reply.into_iter() };
        Ok(Box::new(iter.filter(move |rule| rule.get_table().unwrap() == table_id.into())))
    }
}


#[derive(Debug)]
pub struct Rule {
    packet: NetlinkPacket<'static>,
}

impl Rule {
    
    /// Get the rule's priority
    pub fn get_priority(&self) -> Option<u32> {
        let mut toReturn = None;
        if let Some(rtm) = FibRulePacket::new(&self.packet.payload()[0..]) {
            let payload = &rtm.payload()[0..];
            let iter = RtAttrIterator::new(payload);
            for rta in iter {
                if rta.get_rta_type() == FRA_PRIORITY {
                    let mut cur = Cursor::new(rta.payload());
                    toReturn = Some(cur.read_u32::<LittleEndian>().unwrap());
                }
            }
        }
        return toReturn;
    }

    /// Get the route's table
    pub fn get_table(&self) -> Option<u32> {
        let mut toReturn = None;
        if let Some(rtm) = FibRulePacket::new(&self.packet.payload()[0..]) {
            let payload = &rtm.payload()[0..];
            let iter = RtAttrIterator::new(payload);
            for rta in iter {
                if rta.get_rta_type() == FRA_TABLE {
                    let mut cur = Cursor::new(rta.payload());
                    toReturn = Some(cur.read_u32::<LittleEndian>().unwrap());
                }
            }
        }
        return toReturn;
    }

    /// Get the route's out interface name
    pub fn get_outgoing_interface_name(&self) -> Option<String> {
        let mut toReturn = None;
        if let Some(rtm) = FibRulePacket::new(&self.packet.payload()[0..]) {
            let payload = &rtm.payload()[0..];
            let iter = RtAttrIterator::new(payload);
            for rta in iter {
                if rta.get_rta_type() == FRA_OIFNAME {
                    toReturn = Some(String::from_utf8(Vec::from(rta.payload())).unwrap());
                }
            }
        }
        return toReturn;
    }

    /// Get the route's in interface name
    pub fn get_ingoing_interface_name(&self) -> Option<String> {
        let mut toReturn = None;
        if let Some(rtm) = FibRulePacket::new(&self.packet.payload()[0..]) {
            let payload = &rtm.payload()[0..];
            let iter = RtAttrIterator::new(payload);
            for rta in iter {
                if rta.get_rta_type() == FRA_IFNAME {
                    toReturn = Some(String::from_utf8(Vec::from(rta.payload())).unwrap());
                }
            }
        }
        return toReturn;
    }

    /// Get the route's source port range
    pub fn get_source_port_range(&self) -> Option<[u16; 2]> {
        let mut toReturn = None;
        if let Some(rtm) = FibRulePacket::new(&self.packet.payload()[0..]) {
            let payload = &rtm.payload()[0..];
            let iter = RtAttrIterator::new(payload);
            for rta in iter {
                if rta.get_rta_type() == FRA_SPORT_RANGE {
                    let mut cur = Cursor::new(rta.payload());
                    let port1 = cur.read_u16::<LittleEndian>().unwrap();
                    let port2 = cur.read_u16::<LittleEndian>().unwrap();
                    toReturn = Some([port1, port2]);
                }
            }
        }
        return toReturn;
    }

    /// Get the route's source port range
    pub fn get_destination_port_range(&self) -> Option<[u16; 2]> {
        let mut toReturn = None;
        if let Some(rtm) = FibRulePacket::new(&self.packet.payload()[0..]) {
            let payload = &rtm.payload()[0..];
            let iter = RtAttrIterator::new(payload);
            for rta in iter {
                if rta.get_rta_type() == FRA_DPORT_RANGE {
                    let mut cur = Cursor::new(rta.payload());
                    let port1 = cur.read_u16::<LittleEndian>().unwrap();
                    let port2 = cur.read_u16::<LittleEndian>().unwrap();
                    toReturn = Some([port1, port2]);
                }
            }
        }
        return toReturn;
    }



    fn dump_rule(msg: NetlinkPacket) {
        use std::ffi::CStr;
        if msg.get_kind() != RTM_NEWRULE {
            return;
        }
        //println!("NetLink pkt {:?}", msg);
        if let Some(rtm) = FibRulePacket::new(&msg.payload()[0..]) {
            println!("├ rtm: {:?}", rtm);
            let payload = &rtm.payload()[0..];
            let iter = RtAttrIterator::new(payload);
            for rta in iter {
                match rta.get_rta_type() {
                    FRA_PRIORITY => {
                        let mut cur = Cursor::new(rta.payload());
                        let prio = cur.read_u32::<LittleEndian>().unwrap();
                        println!(" ├ PRIORITY: {:?}", prio);
                    },
                    FRA_SUPPRESS_PREFIXLEN => {
                        println!(" ├ SUPPRESS PREFIXLEN: {:?}", rta.payload());
                    },
                    FRA_TABLE => {
                        let mut cur = Cursor::new(rta.payload());
                        let table = cur.read_u32::<LittleEndian>().unwrap();
                        println!(" ├ TABLE: {:?}", table);
                    },
                    _ => {
                        let rta_values = [ "FRA_UNSPEC", "FRA_DST", "FRA_SRC", "FRA_IFNAME", "FRA_GOTO", "FRA_UNUSED2", "FRA_PRIORITY", "FRA_UNUSED3", "FRA_UNUSED4", "FRA_UNUSED5", "FRA_FWMARK", "FRA_FLOW", "FRA_TUN_ID", "FRA_SUPPRESS_IFGROUP", "FRA_SUPPRESS_PREFIXLEN", "FRA_TABLE", "FRA_FWMASK", "FRA_OIFNAME", "FRA_PAD", "FRA_L3MDEV", "FRA_UID_RANGE", "FRA_PROTOCOL", "FRA_IP_PROTO", "FRA_SPORT_RANGE", "FRA_DPORT_RANGE", "__FRA_MAX" ];
                        let index: usize = rta.get_rta_type() as usize;
                        println!(" ├ {} ({})\t{:x?}", rta_values[index], rta.get_rta_type(), rta.payload());
                    }
                }
            }
        }
    }
}

pub struct RulesIterator<R: Read> {
    iter: NetlinkBufIterator<R>,
}

impl<R: Read> Iterator for RulesIterator<R> {
    type Item = Rule;

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.next() {
            Some(pkt) => {
                let kind = pkt.get_kind();
                if kind != RTM_NEWRULE {
                    return None;
                }
                return Some(Rule { packet: pkt });
            },
            None => None,
        }
    }
}

#[test]
fn dump_rules() {
    let mut conn = NetlinkConnection::new();
    for rule in conn.iter_rules().unwrap() {
        Rule::dump_rule(rule.packet);
    }
}
