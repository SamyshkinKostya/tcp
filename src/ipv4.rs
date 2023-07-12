use anyhow::Result;

use crate::utils::*;

#[derive(Debug)]
pub struct IPv4Header<'a>
{
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub time_to_live: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source_ip: u32,
    pub dest_ip: u32,
    pub options: &'a[u8],
}

impl<'a> IPv4Header<'a>
{
    // https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Header
    pub fn new(data: &'a [u8]) -> Result<(IPv4Header<'a>, &[u8])>
    {
        let ihl = data[0] & 0b00001111;

        Ok((IPv4Header
        {
            version: data[0] >> 4,
            ihl,
            dscp: data[1] >> 2,
            ecn: data[1] & 0b00000011,
            total_length: u16::from_be_bytes(data[2..4].try_into()?),
            identification: u16::from_be_bytes(data[4..6].try_into()?),
            flags: data[6] >> 5,
            fragment_offset: u16::from_be_bytes(data[6..8].try_into()?) & 0b0001111111111111,
            time_to_live: data[8],
            protocol: data[9],
            header_checksum: u16::from_be_bytes(data[10..12].try_into()?),
            source_ip: u32::from_be_bytes(data[12..16].try_into()?),
            dest_ip: u32::from_be_bytes(data[16..20].try_into()?),
            options: &data[20..ihl as usize * 4],
        }, &data[ihl as usize * 4..]))
    }

    pub fn serialize(&self) -> Vec<u8>
    {
        let mut data = vec![0; 56];

        data[0] = self.ihl + (self.version << 4);
        data[1] = self.ecn + (self.dscp << 2);
        set_u16_be(&mut data[2..4], self.total_length);
        set_u16_be(&mut data[4..6], self.identification);
        set_u16_be(&mut data[6..8], (self.fragment_offset + (self.flags as u16)) << 13);
        data[8] = self.time_to_live;
        data[9] = self.protocol;
        set_u16_be(&mut data[10..12], self.header_checksum);
        set_u32_be(&mut data[12..16], self.source_ip);
        set_u32_be(&mut data[16..20], self.dest_ip);
        data[20..self.size()].copy_from_slice(self.options);

        data
    }

    pub fn calc_checksum(&self) -> u16
    {
        let mut data = self.serialize();
        let mut sum = 0;
        
        if data.len() % 2 != 0
        {
            data.push(0);
        }

        for i in (0..data.len()).step_by(2)
        {
            if i == 10 { continue }; // ignore the checksum field

            sum += u16::from_be_bytes(data[i..i + 2].try_into().unwrap()) as u32;
            
            // This is a cool trick and all
            // But lets use overflowing_add
            // It would make this more readable imo
            sum += sum >> 16;
            sum &= 0x0000FFFF;
        }

        !sum as u16
    }

    pub fn size(&self) -> usize
    {
        self.ihl as usize * 4
    }
}
