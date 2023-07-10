use std::ops::BitOr;

use anyhow::Result;

use crate::{utils::*, ipv4};

pub enum TcpFlag
{
    Cwr = 0b10000000,
    Ece = 0b01000000,
    Urg = 0b00100000,
    Ack = 0b00010000,
    Psh = 0b00001000,
    Rst = 0b00000100,
    Syn = 0b00000010,
    Fin = 0b00000001,    
}

impl BitOr<TcpFlag> for TcpFlag
{
    type Output = u8;

    fn bitor(self, rhs: TcpFlag) -> Self::Output
    {
        self as u8 | rhs as u8
    }
}

#[derive(Debug)]
pub struct TcpHeader<'a>
{
    pub source_port: u16,
    pub dest_port: u16,
    pub sequence_number: u32,
    pub ack_number: u32,
    pub data_offset: u8,
    pub flags: u8,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: &'a[u8],
}

impl<'a> TcpHeader<'a>
{
    // https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
    pub fn new(data: &'a [u8]) -> Result<(TcpHeader<'a>, &[u8])>
    {
        let data_offset = data[12] >> 4;

        Ok((TcpHeader
        {
            source_port: u16::from_be_bytes(data[0..2].try_into()?),
            dest_port: u16::from_be_bytes(data[2..4].try_into()?),
            sequence_number: u32::from_be_bytes(data[4..8].try_into()?),
            ack_number: u32::from_be_bytes(data[8..12].try_into()?),
            data_offset,
            flags: data[13],
            window_size: u16::from_be_bytes(data[14..16].try_into()?),
            checksum: u16::from_be_bytes(data[16..18].try_into()?),
            urgent_pointer: u16::from_be_bytes(data[18..20].try_into()?),
            options: &data[20..data_offset as usize * 4],
        }, &data[data_offset as usize * 4..]))
    }
    
    pub fn size(&self) -> usize
    {
        self.data_offset as usize * 4
    }

    pub fn serialize(&self) -> Vec<u8>
    {
        let mut data = vec![0; 56];

        set_u16_be(&mut data[0..2], self.source_port);
        set_u16_be(&mut data[2..4], self.dest_port);
        set_u32_be(&mut data[4..8], self.sequence_number);
        set_u32_be(&mut data[8..12], self.ack_number);
        data[12] = self.data_offset << 4;
        data[13] = self.flags;
        set_u16_be(&mut data[14..16], self.window_size);
        set_u16_be(&mut data[16..18], self.checksum);
        set_u16_be(&mut data[18..20], self.urgent_pointer);
        data[20..self.size()].copy_from_slice(self.options);

        data
    }

    pub fn calc_checksum(&self, source_ip: u32, dest_ip: u32, data_length: usize, text: &[u8]) -> u16
    {
        let mut data = vec![0; data_length + 12];
        let mut sum = 0;

        set_u32_be(&mut data[0..4], source_ip);
        set_u32_be(&mut data[4..8], dest_ip);
        data[9] = 6; // protocol
        set_u16_be(&mut data[10..12], data_length as u16);
        data[12..self.size() + 12].copy_from_slice(&self.serialize()[0..self.size()]);
        data[self.size() + 12..data_length + 12].copy_from_slice(text);

        if data.len() % 2 != 0
        {
            data.push(0);
        }

        for i in (0..data.len()).step_by(2)
        {
            if i == 28 { continue }; // ignore the checksum field

            sum += u16::from_be_bytes(data[i..i + 2].try_into().unwrap()) as u32;
            
            sum += sum >> 16;
            sum &= 0x0000FFFF;
        }

        !sum as u16
    }

    pub fn get_flag(&self, flag: TcpFlag) -> bool
    {
        self.flags & flag as u8 != 0
    }

    pub fn set_flag(&mut self, flag: TcpFlag, value: bool)
    {
        if value { self.flags |= flag as u8 }
        else { self.flags &= !(flag as u8) }
    }
}

// Maybe this function should be split into multiple:
// maybe TcpHeader::new? IPv4Header::new? serialize?
pub fn build_tcp_packet(orig_ip: &ipv4::IPv4Header, orig_tcp: &TcpHeader, flags: u8, seq_num: u32, ack_num: u32, text: &[u8]) -> Vec<u8>
{
    let mut tcp = TcpHeader
    {
        source_port: orig_tcp.dest_port,
        dest_port: orig_tcp.source_port,
        sequence_number: seq_num,
        ack_number: ack_num,
        data_offset: 0,
        flags,
        window_size: 1500,
        checksum: 0,
        urgent_pointer: 0,
        options: &[0; 0],
    };

    let mut ip = ipv4::IPv4Header
    {
        version: 4,
        ihl: 5,
        dscp: 0,
        ecn: 0,
        total_length: 40 + text.len() as u16, // Some magic numbers
        identification: 0,
        flags: 0b000,
        fragment_offset: 0,
        time_to_live: 64,
        protocol: 6, // tcp                   // More magic numbers. This is used multiple times even
        header_checksum: 0, // filled out later
        source_ip: orig_ip.dest_ip,
        dest_ip: orig_ip.source_ip,
        options: &[0; 0],
    };
    ip.header_checksum = ip.calc_checksum();

    tcp.data_offset = 5;
    tcp.checksum = tcp.calc_checksum(ip.source_ip, ip.dest_ip, tcp.size() + text.len(), text);

    let mut output = vec![0; 44 + text.len()];
    set_u16_be(&mut output[2..4], 0x0800);
    output[4..24].copy_from_slice(&ip.serialize()[0..20]);
    output[24..44].copy_from_slice(&tcp.serialize()[0..20]);
    output[44..44 + text.len()].copy_from_slice(text);
    output
}
