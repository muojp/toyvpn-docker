use std::net::Ipv4Addr;

/// Build VPN parameters to send to the client
pub fn build_client_parameters(
    client_ip: Ipv4Addr,
    args: &[String],
) -> Vec<u8> {
    let mut parameters = vec![0u8; 1024];
    let mut offset = 0;

    log::debug!("Generating parameters with IP: {}", client_ip);

    let mut skip_count = 0;

    for (i, arg) in args.iter().enumerate() {
        if skip_count > 0 {
            skip_count -= 1;
            continue;
        }

        let mut param = arg.as_str();
        let mut delimiter = b',';

        // Handle flag format: "-a" becomes "a"
        if arg.len() == 2 && arg.starts_with('-') {
            param = &arg[1..];
            delimiter = b' ';
        }

        log::debug!("Processing parameter: {}", param);

        // Check if this is the address parameter flag '-a' or direct 'a,'
        if param.len() == 1 && param == "a" {
            // This is '-a' flag format, next two args are IP and prefix
            if i + 2 < args.len() {
                let new_param = format!("a,{},32", client_ip);
                log::debug!("Replacing -a flag address with: {}", new_param);

                if offset + new_param.len() + 1 >= parameters.len() {
                    log::error!("Parameters are too large");
                    break;
                }

                parameters[offset] = delimiter;
                parameters[offset + 1..offset + 1 + new_param.len()]
                    .copy_from_slice(new_param.as_bytes());
                offset += 1 + new_param.len();

                // Skip next two arguments (IP and prefix)
                skip_count = 2;
                continue;
            }
        } else if param.len() >= 2 && param.starts_with("a,") {
            // Direct 'a,IP,prefix' format
            let new_param = format!("a,{},32", client_ip);
            log::debug!("Replacing address parameter with: {}", new_param);

            if offset + new_param.len() + 1 >= parameters.len() {
                log::error!("Parameters are too large");
                break;
            }

            parameters[offset] = delimiter;
            parameters[offset + 1..offset + 1 + new_param.len()]
                .copy_from_slice(new_param.as_bytes());
            offset += 1 + new_param.len();
            continue;
        }

        // Normal parameter - copy as is
        if offset + param.len() + 1 >= parameters.len() {
            log::error!("Parameters are too large");
            break;
        }

        parameters[offset] = delimiter;
        parameters[offset + 1..offset + 1 + param.len()].copy_from_slice(param.as_bytes());
        offset += 1 + param.len();
    }

    // Fill rest with spaces
    for i in offset..parameters.len() {
        parameters[i] = b' ';
    }
    parameters[0] = 0;

    log::debug!("Final parameters: {}", String::from_utf8_lossy(&parameters[1..100]));

    parameters
}

/// Parse IPv4 header to extract source and destination IPs
#[derive(Debug, Clone, Copy)]
pub struct IpPacket {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    #[allow(dead_code)]
    pub version: u8,
}

impl IpPacket {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }

        let version = (data[0] >> 4) & 0x0F;
        if version != 4 {
            return None;
        }

        let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

        Some(Self { src, dst, version })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_parameters() {
        let args = vec![
            "toyvpn-server".to_string(),
            "tun0".to_string(),
            "8000".to_string(),
            "secret".to_string(),
            "a,172.31.0.1,32".to_string(),
            "m,1400".to_string(),
            "r,0.0.0.0,0".to_string(),
        ];

        let ip = Ipv4Addr::new(172, 31, 0, 5);
        let params = build_client_parameters(ip, &args[4..]);

        let params_str = String::from_utf8_lossy(&params);
        assert!(params_str.contains("a,172.31.0.5,32"));
        assert!(params_str.contains("m,1400"));
    }

    #[test]
    fn test_parse_ip_packet() {
        // Minimal IPv4 packet header
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45; // Version 4, IHL 5
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]); // Source
        packet[16..20].copy_from_slice(&[192, 0, 2, 2]); // Dest

        let ip = IpPacket::parse(&packet).unwrap();
        assert_eq!(ip.version, 4);
        assert_eq!(ip.src, Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(ip.dst, Ipv4Addr::new(192, 0, 2, 2));
    }
}
