use std::collections::VecDeque;

use anyhow::Result;
use chrono::Local;
use colored::Colorize;
use rand::Rng;
use tun_tap::{ Iface, Mode };

mod utils;

mod ipv4;
use ipv4::IPv4Header;

mod tcp;
use tcp::{ TcpHeader, TcpFlag, build_tcp_packet };
use utils::wrapping_between;

#[derive(Debug, PartialEq)]
enum State
{
    Closed,
    Listen,
    SynRecvd,
    Estab,
    LastAck,
}

#[derive(Debug)]
struct Connection
{
    state: State,
    recv_seq: u32,
    send_seq: u32,
    send_window: u16,
    packet_queue: VecDeque<u8>,
}

impl Connection
{
    fn new() -> Connection
    {
        Connection
        {
            state: State::Listen,
            recv_seq: 0,
            send_seq: rand::thread_rng().gen(),
            send_window: 0,
            packet_queue: VecDeque::new(),
        }
    }

    // This code is basically the same. Maybe there is a way to unify it?
    fn clear(&mut self)
    {
        self.state = State::Listen;
        self.recv_seq = 0;
        self.send_seq = rand::thread_rng().gen();
        self.send_window = 0;
        self.packet_queue.clear();
    }
}

fn main() -> Result<()>
{
    let mut conn = Connection::new();
    let iface = Iface::new("tun0", Mode::Tun)?;
    let mut buf = [0; 1504];

    loop
    {
        if conn.state == State::Closed
        {
            println!("listening again");
            conn.clear();
        }

        let recv_size = iface.recv(&mut buf)?;

        let proto = u16::from_be_bytes(buf[2..4].try_into()?);        
        if proto != 0x0800 { continue }; // only allow IPv4, https://en.wikipedia.org/wiki/EtherType#Values

        let (ip, data) = IPv4Header::new(&buf[4..recv_size])?;
        if ip.protocol != 6 { continue }; // only allow TCP, https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Data
        if ip.header_checksum != ip.calc_checksum()
        {
            println!("invalid ip checksum");
            continue;
        }

        let (tcp, data) = TcpHeader::new(data)?;
        if tcp.checksum != tcp.calc_checksum(ip.source_ip, ip.dest_ip, tcp.size() + data.len(), data)
        {
            println!("invalid tcp checksum");
            continue;
        }

        // We do not check that the packet belongs to the connection established

        match conn.state
        {
            State::Listen if tcp.get_flag(TcpFlag::Syn) =>
            {
                // Syn-Ack in this situation is invalid and should be treated with Rst
                println!("got SYN");
    
                conn.state = State::SynRecvd;
                conn.recv_seq = tcp.sequence_number.wrapping_add(1);
                
                iface.send(build_tcp_packet(
                    &ip,
                    &tcp,
                    TcpFlag::Syn | TcpFlag::Ack,
                    conn.send_seq,
                    conn.recv_seq,
                    &[0; 0],
                ).as_slice()).expect("failed to send SYN-ACK");
            },
            State::SynRecvd if tcp.get_flag(TcpFlag::Ack) =>
            {
                // Syn-Ack in this situation is invalid and should be treated with Rst
                if tcp.ack_number != conn.send_seq.wrapping_add(1) || tcp.get_flag(TcpFlag::Syn)
                {
                    println!("got invalid ack, sending RST");

                    conn.state = State::Closed;
                    iface.send(build_tcp_packet(
                        &ip,
                        &tcp,
                        TcpFlag::Rst as u8,
                        tcp.ack_number,
                        tcp.sequence_number + data.len() as u32,
                        &[0; 0],
                    ).as_slice()).expect("failed to send RST");
                    
                    continue;
                }

                println!("got ACK of SYN, connection established");

                conn.send_seq = conn.send_seq.wrapping_add(1);
                conn.state = State::Estab;
            },
            // This should be at the top as the case with highest priority.
            // idk if it is possible to get ack-rst or syn-rst, but either way
            _ if tcp.get_flag(TcpFlag::Rst) =>
            {
                println!("got RST, connection closed");
                conn.state = State::Closed;
            },
            State::Estab if tcp.get_flag(TcpFlag::Fin) =>
            {
                println!("got FIN");
                conn.state = State::LastAck;
    
                conn.recv_seq = tcp.sequence_number.wrapping_add(1);
                
                iface.send(build_tcp_packet(
                    &ip,
                    &tcp,
                    TcpFlag::Fin | TcpFlag::Ack,
                    conn.send_seq,
                    conn.recv_seq,
                    &[0; 0],
                ).as_slice()).expect("failed to send FIN-ACK");
            },
            State::LastAck if tcp.get_flag(TcpFlag::Ack) =>
            {
                println!("got ACK of FIN, connection closed");
                conn.state = State::Closed;
            },
            State::Estab =>
            {
                if !tcp.get_flag(TcpFlag::Ack)
                {
                    println!("ACK not set");
                    continue;
                }

                // Also, tcp.sequence_number can be difference from conn.recv_seq
                // xx is the segment we receive
                // --|xx--|-- what you process now
                // -x|x---|-- also legal
                // --|-xx-|-- also legal, but harder to implement, lets skip for now
                if tcp.sequence_number != conn.recv_seq
                    || !wrapping_between(
                        conn.send_seq,
                        tcp.ack_number,
                        conn.send_seq.wrapping_add(conn.send_window as u32))
                {
                    println!("sending an empty packet");

                    // &Vec<T> can dereference to &[T]
                    iface.send(build_tcp_packet(
                        &ip,
                        &tcp,
                        TcpFlag::Ack as u8,
                        conn.send_seq,
                        conn.recv_seq,
                        &[0; 0],
                    ).as_slice()).expect("failed to send an empty packet");

                    continue;
                }

                println!("RECV {tcp:?}");
                println!("{data:02X?}");

                conn.send_window = tcp.window_size;
                conn.recv_seq = conn.recv_seq.wrapping_add(data.len() as u32);

                // What if tcp.ack_number wraps? 
                if conn.send_seq < tcp.ack_number
                {
                    // Not wrapping!
                    let amount = tcp.ack_number - conn.send_seq;
                    conn.send_seq = tcp.ack_number;
                    conn.packet_queue.drain(..amount as usize);
                }
                
                let msg = std::str::from_utf8(data).unwrap();
                match msg.to_lowercase().trim()
                {
                    _ if data.is_empty() => { continue; },
                    "fin" =>
                    {
                        conn.state = State::LastAck;

                        iface.send(build_tcp_packet(
                            &ip,
                            &tcp,
                            TcpFlag::Fin | TcpFlag::Ack,
                            conn.send_seq,
                            conn.recv_seq,
                            &[0; 0],
                        ).as_slice()).expect("failed to send FIN");
                    },
                    "rst" =>
                    {
                        conn.state = State::Closed;

                        // Also duplicate with 125
                        iface.send(build_tcp_packet(
                            &ip,
                            &tcp,
                            TcpFlag::Rst as u8,
                            conn.send_seq,
                            conn.recv_seq,
                            &[0; 0],
                        ).as_slice()).expect("failed to send RST");

                        continue;
                    },
                    "help" =>
                    {
                        let msg = format!("{}\nfin - Close the connection
rst - Reset the connection
time - Show server time
conn - Show the connection struct
clear - Clear the screen", "----- Help -----".bold()).green().to_string();
                        conn.packet_queue.extend(msg.as_bytes());
                    },
                    "time" =>
                    {
                        let msg = format!("{} {}", "Time:".cyan(), Local::now().format("%H:%M:%S").to_string().cyan().bold());
                        conn.packet_queue.extend(msg.as_bytes());
                    },
                    "conn" =>
                    {
                        let msg = format!("{conn:?}");
                        // Maybe use magenta only once?
                        let msg = format!("{} {}", "conn =".magenta(), msg.magenta().bold());
                        conn.packet_queue.extend(msg.as_bytes()); 
                    },
                    "clear" =>
                    {
                        conn.packet_queue.extend("\x1B[2J\x1B[H".as_bytes()); 
                    },
                    _ =>
                    {
                        let msg = format!("Invalid command. Try \"{}\"", "help".underline()).red().bold().to_string();
                        // You have this | exact line repeated like 5 times. Refactor?
                        //               v
                        conn.packet_queue.extend(msg.as_bytes());
                    },
                }

                conn.packet_queue.extend("\n> ".as_bytes());

                let text: &[u8] = if !conn.packet_queue.is_empty()
                {
                    let size = std::cmp::min(conn.packet_queue.len(), conn.send_window.into());
                    &conn.packet_queue.make_contiguous()[..size]
                }
                else
                {
                    &[0; 0]
                };

                println!("SEND ACK seq={} ack={}", conn.send_seq, conn.recv_seq);
                iface.send(build_tcp_packet(
                    &ip,
                    &tcp,
                    TcpFlag::Ack as u8,
                    conn.send_seq,
                    conn.recv_seq,
                    text,
                ).as_slice()).expect("failed to send ACK");
            },
            // Rst flag (if any) was caught in an earlier case
            State::Closed if !tcp.get_flag(TcpFlag::Rst) =>
            {
                println!("got a packet in a closed connection, sending RST");

                // This seems to be the exact code from line 125
                // Maybe it can be united/refactored to remove duplication
                iface.send(build_tcp_packet(
                    &ip,
                    &tcp,
                    TcpFlag::Rst as u8,
                    if tcp.get_flag(TcpFlag::Ack) { tcp.ack_number } else { 0 },
                    tcp.sequence_number + data.len() as u32,
                    &[0; 0],
                ).as_slice()).expect("failed to send RST");
            },
            _ =>
            {
                println!("UNKNOWN packet - state={:?} {tcp:?}", conn.state);
            },
        }
    }
}
