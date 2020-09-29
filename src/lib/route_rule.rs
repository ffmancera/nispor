use crate::netlink::parse_as_ipv4;
use crate::netlink::parse_as_ipv6;
use crate::NisporError;
use crate::route::AddressFamily;
use crate::route::RouteProtocol;
use futures::stream::TryStreamExt;
use netlink_packet_route::RuleMessage;
use netlink_packet_route::rtnl::rule::nlas::Nla;
use rtnetlink::new_connection;
use rtnetlink::IpVersion;
use serde_derive::{Deserialize, Serialize};
use tokio::runtime::Runtime;

const FR_ACT_TO_TBL: u8 = 1;
const FR_ACT_TO_GOTO: u8 = 2;
const FR_ACT_TO_NOP: u8 = 4;
const FR_ACT_TO_RES3: u8 = 8;
const FR_ACT_TO_RES4: u8 = 16;
const FR_ACT_TO_BLACKHOLE: u8 = 32;
const FR_ACT_TO_PROHIBIT: u8 = 64;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum RuleAction {
    /* Pass to fixed table */
    Tbl,
    /* Jump to another rule */
    Goto,
    /* No operation */
    Nop,
    Res3,
    Res4,
    /* Drop without notification */
    Blackhole,
    /* Drop with ENETUNREACH */
    Unreachable,
    /* Drop with EACCES */
    Prohibit,
    Other(u8),
    Unknown,
}

impl From<u8> for RuleAction {
    fn from(d: u8) -> Self {
        match d {
            FR_ACT_TO_TBL => Self::Tbl,
            FR_ACT_TO_GOTO => Self::Goto,
            FR_ACT_TO_NOP => Self::Nop,
            FR_ACT_TO_RES3 => Self::Res3,
            FR_ACT_TO_RES4 => Self::Res4,
            FR_ACT_TO_BLACKHOLE => Self::Blackhole,
            FR_ACT_TO_PROHIBIT => Self::Prohibit,
            _ => Self::Other(d),
        }
    }
}

impl Default for RuleAction {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct RouteRule {
    pub action: RuleAction,
    pub address_family: AddressFamily,
    pub flags: u32,
    pub table: u32,
    pub tos: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iif: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oif: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goto: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fw_mark: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fw_mask: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mask: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tun_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppress_ifgroup: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppress_prefix_len: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<RouteProtocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_proto: Option<AddressFamily>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_port_range: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_port_range: Option<Vec<u8>>,
}

pub(crate) fn get_route_rules() -> Result<Vec<RouteRule>, NisporError> {
    Ok(Runtime::new()?.block_on(_get_route_rules())?)
}

async fn _get_route_rules() -> Result<Vec<RouteRule>, NisporError> {
    let mut rules = Vec::new();
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    let mut links = handle.rule().get(IpVersion::V6).execute();
    while let Some(rt_msg) = links.try_next().await? {
        rules.push(get_rule(rt_msg)?);
    }
    let mut links = handle.rule().get(IpVersion::V4).execute();
    while let Some(rt_msg) = links.try_next().await? {
        rules.push(get_rule(rt_msg)?);
    }
    Ok(rules)
}

fn get_rule(rule_msg: RuleMessage) -> Result<RouteRule, NisporError> {
    let mut rl = RouteRule::default();
    let header = &rule_msg.header;
    rl.address_family = header.family.into();
    let src_prefix_len = header.src_len;
    let dst_prefix_len = header.dst_len;
    rl.table = header.table.into();
    rl.tos = header.tos;
    rl.action = header.action.into();
    let family = &rl.address_family;
    for nla in &rule_msg.nlas {
        match nla {
        Nla::Destination(ref d) => {
            rl.dst = Some(format!(
                "{}/{}",
                _addr_to_string(d, family),
                dst_prefix_len,
            ));
        }
        Nla::Source(ref d) => {
            rl.src = Some(format!(
                "{}/{}",
                _addr_to_string(d, family),
                src_prefix_len,
            ));
        }
        Nla::Iifname(ref d) => {
            rl.iif = Some(d.clone().to_string());
        }
        Nla::OifName(ref d) => {
            rl.oif = Some(d.clone().to_string());
        }
        Nla::Goto(ref d) => {
            rl.goto = Some(*d);
        }
        Nla::Priority(ref d) => {
            rl.priority = Some(*d);
        }
        Nla::FwMark(ref d) => {
            rl.fw_mark = Some(*d);
        }
        Nla::FwMask(ref d) => {
            rl.fw_mask = Some(*d);
        }
        Nla::Flow(ref d) => {
            rl.flow = Some(*d);
        }
        Nla::TunId(ref d) => {
            rl.tun_id = Some(*d);
        }
        Nla::SuppressIfGroup(ref d) => {
            rl.suppress_ifgroup = Some(*d);
        }
        Nla::SuppressPrefixLen(ref d) => {
            rl.suppress_prefix_len = Some(*d);
        }
        Nla::Table(ref d) => {
            rl.table = *d;
        }
        Nla::Protocol(ref d) => {
            rl.protocol = Some(d.clone().into());
        }
        Nla::IpProto(ref d) => {
            rl.ip_proto = Some(d.clone().into());
        }
        _ => eprintln!("Unknown NLA message for route {:?}", nla),
    }
}

Ok(rl)
}

fn _addr_to_string(data: &[u8], family: &AddressFamily) -> String {
    match family {
        AddressFamily::IPv4 => parse_as_ipv4(data),
        AddressFamily::IPv6 => parse_as_ipv6(data),
        _ => format!("{:?}", data),
    }
}
