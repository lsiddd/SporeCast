use log::{debug, info, warn};
use maxminddb::{geoip2, Reader};
use serde_json::{json, Value};
use std::net::IpAddr;
use std::str::FromStr;

pub struct GeoIpEnricher {
    reader: Reader<Vec<u8>>,
}

impl GeoIpEnricher {
    pub fn open(path: &str) -> Option<Self> {
        match Reader::open_readfile(path) {
            Ok(reader) => {
                info!("GeoIP database loaded from {}", path);
                Some(Self { reader })
            }
            Err(e) => {
                warn!(
                    "GeoIP database unavailable at {}: {}. GeoIP enrichment disabled.",
                    path, e
                );
                None
            }
        }
    }

    pub fn lookup(&self, ip_str: &str) -> Option<Value> {
        let ip = IpAddr::from_str(ip_str).ok()?;
        let city: geoip2::City = self.reader.lookup(ip).ok()?;

        let country_code = city
            .country
            .as_ref()
            .and_then(|c| c.iso_code)
            .unwrap_or("XX");

        let country_name = city
            .country
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|n| n.get("en").copied())
            .unwrap_or("Unknown");

        let city_name = city
            .city
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|n| n.get("en").copied())
            .unwrap_or("Unknown");

        let (lat, lon) = city
            .location
            .as_ref()
            .and_then(|l| l.latitude.zip(l.longitude))
            .unwrap_or((0.0, 0.0));

        debug!(
            "GeoIP {}: {} / {} ({}, {})",
            ip_str, country_code, city_name, lat, lon
        );

        Some(json!({
            "country_code": country_code,
            "country_name": country_name,
            "city": city_name,
            "location": { "lat": lat, "lon": lon }
        }))
    }
}

impl crate::domain::ports::GeoIpLookup for GeoIpEnricher {
    fn lookup(&self, ip_str: &str) -> Option<Value> {
        GeoIpEnricher::lookup(self, ip_str)
    }
}
