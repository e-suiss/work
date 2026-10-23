use crate::TestkitError;

const COMPOSE: &str = include_str!("../../../deploy/compose/compose.yaml");

/// A container image pinned to a digest, as `deploy/compose/compose.yaml` names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef {
    /// Repository, e.g. `postgres`.
    pub repository: String,
    /// Digest, e.g. `sha256:…`.
    pub digest: String,
}

impl ImageRef {
    /// `repository@digest`.
    #[must_use]
    pub fn reference(&self) -> String {
        format!("{}@{}", self.repository, self.digest)
    }

    pub(crate) fn generic(&self) -> testcontainers::GenericImage {
        let (algorithm, hex) = self
            .digest
            .split_once(':')
            .unwrap_or(("sha256", &self.digest));
        testcontainers::GenericImage::new(
            format!("{}@{algorithm}", self.repository),
            hex.to_owned(),
        )
    }
}

/// The digest-pinned image of a compose service; tests and the local environment
/// run the same bytes (T-36, T-41).
///
/// # Errors
///
/// [`TestkitError::ImageNotPinned`] if the service has no `image: name@sha256:…` line.
pub fn compose_image(service: &'static str) -> Result<ImageRef, TestkitError> {
    image_in(COMPOSE, service).ok_or(TestkitError::ImageNotPinned { service })
}

fn image_in(compose: &str, service: &str) -> Option<ImageRef> {
    let header = format!("  {service}:");
    let mut lines = compose
        .lines()
        .skip_while(|l| l.trim_end() != header)
        .skip(1);
    lines
        .by_ref()
        .take_while(|l| l.is_empty() || l.starts_with("    ") || l.trim_start().starts_with('#'))
        .find_map(|l| l.trim().strip_prefix("image:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.split_once('@'))
        .filter(|(_, d)| d.starts_with("sha256:") && d.len() == 71)
        .map(|(r, d)| ImageRef {
            repository: r.to_owned(),
            digest: d.to_owned(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_36_postgres_and_nats_images_come_from_the_compose_pins() {
        for service in ["postgres", "nats"] {
            let image = compose_image(service).unwrap();
            let line = format!("image: {}", image.reference());
            assert!(COMPOSE.contains(&line), "{service}: {line}");
            assert_eq!(image.repository, service);
        }
    }

    #[test]
    fn t_36_unpinned_or_missing_images_are_rejected() {
        let compose = "services:\n  a:\n    image: a:1.0\n  b:\n    build: ./b\n  c:\n    image: c@sha256:00\n";
        assert_eq!(image_in(compose, "a"), None);
        assert_eq!(image_in(compose, "b"), None);
        assert_eq!(image_in(compose, "c"), None);
        assert_eq!(image_in(compose, "d"), None);
    }

    #[test]
    fn t_36_an_image_line_belongs_to_its_own_service() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let compose =
            format!("services:\n  a:\n    build: ./a\n  b:\n    image: b@{digest} # 1.0\n");
        assert_eq!(image_in(&compose, "a"), None);
        assert_eq!(
            image_in(&compose, "b"),
            Some(ImageRef {
                repository: "b".to_owned(),
                digest,
            })
        );
    }
}
