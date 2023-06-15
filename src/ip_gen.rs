use anyhow::{anyhow, Context, Ok, Result};
use blake3::{hash, Hash};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use nftnl::expr::ToSlice;
use std::{borrow::Borrow, net::*};

pub fn gen_bytes(mut name: String) -> Hash {
    name.push_str("_netnsp"); // avoid collision with other apps, if ever
    let hashed = hash(name.as_bytes());
    hashed
}

// gen network address for namespace, or full address given name
pub fn gen_ip(
    prefix: IpNetwork,    // the prefix ALL generated addresses must conform
    namespace: String,    // IPs of same namespace have the same prefix up to $len
    name: Option<String>, // Iff IPs are of the same name, they have the same suffix
    len: u8,
) -> IpNetwork {
    // prefix_bits | namespace bits | name bits
    assert!(len > prefix.prefix());
    match prefix.network() {
        // only network part, the rest is 0
        IpAddr::V4(pre_net_ip) => {
            let pre_net = pre_net_ip.octets();
            let namespace_bytes = gen_bytes(namespace);

            assert_eq!(pre_net.len(), 4);
            let ns_hash: &[u8; 4] = &namespace_bytes.as_bytes()[0..=3].try_into().unwrap();

            let mask = prefix.mask();
            let IpAddr::V4(maskv4) = mask            
                else {
                unreachable!() 
             };
            
            let filtered = bitwise_op(&maskv4.octets(), ns_hash, |a, b| !a & b); // take the right half of hash
            let combined = bitwise_op(&pre_net, &filtered, |a, b| a | b); // take prefix as the left half
            let ns_ip = Ipv4Addr::from(combined).into(); // | prefix | hash |
            let ns_net: Ipv4Network = Ipv4Network::new(ns_ip, len).unwrap(); // the results are meant to have network part of $len

            if name.is_none() {
                ns_net.into()
            } else {
                let name_hash = gen_bytes(name.unwrap());
                let filtered = bitwise_op(&ns_net.mask().octets(), &name_hash.as_bytes()[..=3].try_into().unwrap(), |a, b| !a & b); // right half
                let ip_final = bitwise_op(&ns_net.network().octets(), &filtered, |a, b| a | b); // take ns_ip as the left half
                IpNetwork::new(Ipv4Addr::from(ip_final).into(), len).unwrap()
            }
        }
        IpAddr::V6(pre_net_ip) => {
            let pre_net = pre_net_ip.octets();
            let namespace_bytes = gen_bytes(namespace);

            assert_eq!(pre_net.len(), 16);
            let ns_hash: &[u8; 16] = &namespace_bytes.as_bytes()[0..=15].try_into().unwrap();

            let mask = prefix.mask();
            let IpAddr::V6(maskv6) = mask 
                else {
                unreachable!() 
             };

            let filtered = bitwise_op(&maskv6.octets(), ns_hash, |a, b| !a & b);
            let combined = bitwise_op(&pre_net, &filtered, |a, b| a | b);
            let ns_ip = Ipv6Addr::from(combined).into(); // | prefix | hash |
            let ns_net: Ipv6Network = Ipv6Network::new(ns_ip, len).unwrap();
            
            if name.is_none() {
                ns_net.into()
            } else {
                let name_hash = gen_bytes(name.unwrap());
                let filtered = bitwise_op(&ns_net.mask().octets(), &name_hash.as_bytes()[..=15].try_into().unwrap(), |a, b| !a & b);
                let ip_final = bitwise_op(&ns_net.network().octets(), &filtered, |a, b| a | b);

                IpNetwork::new(Ipv6Addr::from(ip_final).into(), len).unwrap()
            }
        }
    }
}

fn bitwise_op<F: Fn(u8, u8) -> u8, const L: usize>(
    array1: &[u8; L],
    array2: &[u8; L],
    op: F,
) -> [u8; L] {
    array1
        .iter()
        .zip(array2.iter())
        .map(|(&a, &b)| op(a,b))
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap()
}

#[test]
fn basic() {
    dbg!(gen_bytes("1".to_string()));
    let num : u32 = 0b1111<<28;
    let n2: u32 = 0b1011_1101<<24;
    let ipv4 = Ipv4Addr::from(num);
    let ip2 = Ipv4Addr::from(n2);
    dbg!(bitwise_op(&ipv4.octets(), &ip2.octets(), |a,b| a|b));
    dbg!((num | n2)>>24);
}

#[test]
fn ips() {
    dbg!(gen_ip(IpNetwork::new([0,0,0,0].into(), 8).unwrap(), "test".to_string(), None, 9));
    dbg!(gen_ip(IpNetwork::new([0,0,0,0].into(), 16).unwrap(), "test".to_string(), None, 17));
    dbg!(gen_ip(IpNetwork::new([12,34,0,0].into(), 16).unwrap(), "test".to_string(), None, 17));
    dbg!(gen_ip(IpNetwork::new([12,255,0,0].into(), 12).unwrap(), "te".to_string(), None, 17));
    dbg!(gen_ip(IpNetwork::new([12,255,0,0].into(), 12).unwrap(), "testx".to_string(), None, 17));
    let net = dbg!(gen_ip(IpNetwork::new([12,255,0,0].into(), 12).unwrap(), "test".to_string(), None, 15).network());
    let ip1 = dbg!(gen_ip(IpNetwork::new([12,255,0,0].into(), 12).unwrap(), "test".to_string(), Some("app1".to_string()), 15)).ip();

    print_ip(net);
    print_ip(ip1);
    print_ip(gen_ip(IpNetwork::new([12,255,0,0].into(), 12).unwrap(), "test".to_string(), Some("app2".to_string()), 15).ip());
    print_ip(gen_ip(IpNetwork::new([12,255,0,0].into(), 12).unwrap(), "test".to_string(), Some("app4".to_string()), 15).ip());
    print_ip(gen_ip(IpNetwork::new([12,255,0,0].into(), 12).unwrap(), "test".to_string(), Some("app5".to_string()), 15).ip());
    print_ip(gen_ip(IpNetwork::new([12,255,0,0].into(), 12).unwrap(), "test".to_string(), Some("app7".to_string()), 15).ip());

    println!("prefix, namespace divide");
    print_ip(IpNetwork::V6("ffff:ffff::0/14".parse().unwrap()).network());
    print_ip(gen_ip(IpNetwork::V6("ffff:ffff::0/14".parse().unwrap()), "test".to_string(), None, 16).ip());
    print_ip(gen_ip(IpNetwork::V6("0:0::0/10".parse().unwrap()), "test".to_string(), None, 16).ip());
    print_ip(gen_ip(IpNetwork::V6("ffff:ffff::0/8".parse().unwrap()), "test".to_string(), None, 27).ip());
    println!("namespace, name divide");
    print_ip(gen_ip(IpNetwork::V6("ffff:ffff::0/14".parse().unwrap()), "test".to_string(), Some("ss".to_string()), 15).ip());
    print_ip(gen_ip(IpNetwork::V6("ffff:ffff::0/14".parse().unwrap()), "test".to_string(), Some("ss".to_string()), 16).ip());
    print_ip(gen_ip(IpNetwork::V6("ffff:ffff::0/14".parse().unwrap()), "test".to_string(), Some("ss".to_string()), 18).ip());
    print_ip(gen_ip(IpNetwork::V6("ffff:ffff::0/14".parse().unwrap()), "test".to_string(), Some("ss".to_string()), 32).ip());
    print_ip(gen_ip(IpNetwork::V6("::/14".parse().unwrap()), "test".to_string(), Some("ss".to_string()), 18).ip());
}

fn print_bits(bytes: &[u8]) {
    for byte in bytes {
        for i in (0..8).rev() {
            print!("{}", (byte >> i) & 1);
        }
        print!(" ");
    }
    print!("\n");
}

fn print_ip(ip: IpAddr) {
    match ip {
        IpAddr::V4(i) => print_bits(&i.octets()),
        IpAddr::V6(i) => print_bits(&i.octets()),
    }
}

#[test]
fn test_ipgen() -> Result<()> {
    let c1 = gen_ip("10.254.0.0/8".parse()?, "cafe".to_string(), None, 16);
    let c2 =  gen_ip("10.254.0.0/8".parse()?,"cafe".to_string(),None, 16);
    let c1n = c1.network();
    let c2n = c2.network();
    assert_eq!(c1n, c2n);
    dbg!(c1n);
    dbg!(c2n);

    dbg!(IpNetwork::new(Ipv4Addr::new(10, 254, 0, 0).into(), 8)?.network()); // 10.0.0.0
    dbg!(IpNetwork::new(Ipv4Addr::new(10, 254, 0, 0).into(), 9)?.network()); // 10.128.0.0

    let c1 = gen_ip("10.254.0.0/8".parse()?, "cafe".to_string(), None, 16);
    let c2 =gen_ip("10.254.0.0/9".parse()?, "cafe".to_string(), None, 16);
    dbg!(c1);
    dbg!(c2);
    let c1n = c1.network();
    let c2n = c2.network();
    assert_ne!(c1n, c2n);
    dbg!(c1n);
    dbg!(c2n);

    Ok(())
}
