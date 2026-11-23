//! The tzdb zones a commitment's clocks and periodic updates count in (CM-50, CM-53, CM-64): every zone of the pinned IANA release vendored in `conformance/tzdb`, read by the kernel's own `TZif` reader only when a definition names it, and reported with its release in every projection.

use work_kernel::tz::Zone;

mod zones;

/// The tzdb release of the zones.
pub const VERSION: &str = zones::VERSION;

/// The zone `name` of the vendored release, if the release has it and its `TZif` reads.
#[must_use]
pub fn zone(name: &str) -> Option<Zone> {
    let index = zones::ZONES.binary_search_by(|(n, _)| n.cmp(&name)).ok()?;
    let (_, bytes) = zones::ZONES.get(index)?;
    Zone::from_tzif(name, VERSION, bytes).ok()
}

/// The zones of `names` the vendored release has, in the order given.
#[must_use]
pub fn zones(names: &[String]) -> Vec<Zone> {
    names.iter().filter_map(|n| zone(n)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // CM-64
    #[test]
    fn cm_64_every_vendored_zone_reads_at_the_pinned_release() {
        assert_eq!(VERSION, "2026f");
        assert!(zones::ZONES.len() > 500);
        assert!(zones::ZONES.windows(2).all(|w| w[0].0 < w[1].0));
        for (name, bytes) in zones::ZONES {
            assert!(
                Zone::from_tzif(name, VERSION, bytes).is_ok(),
                "{name} does not read"
            );
        }
        let berlin = zone("Europe/Berlin").unwrap();
        assert_eq!(berlin.version(), "2026f");
        assert_eq!(berlin.offset_at(1_774_745_999).unwrap(), 3_600);
        assert_eq!(berlin.offset_at(1_774_746_000).unwrap(), 7_200);
        let istanbul = zone("Europe/Istanbul").unwrap();
        assert_eq!(istanbul.offset_at(1_433_116_800).unwrap(), 10_800);
        assert!(zone("Mars/Olympus_Mons").is_none());
        assert_eq!(
            zones(&["UTC".to_owned(), "Nowhere".to_owned()])
                .iter()
                .map(Zone::name)
                .collect::<Vec<_>>(),
            vec!["UTC"]
        );
    }
}
