pub mod cli;
pub mod collectors;
pub mod disk_health_resource_sandbox;
pub mod host_profile;
pub mod metrics;
pub mod observation_runtime;
pub mod probe_auth;
pub mod protocol;
pub mod registration;
pub mod report;
pub mod runtime;
pub mod runtime_failure;
pub mod secure_file;
pub mod system_state_resource_sandbox;
pub mod transport;
pub mod upgrader;
pub mod version;

pub(crate) mod hub_url {
    use url::Url;

    pub(crate) fn normalized_base(hub_url: &str) -> Result<String, ()> {
        Ok(validated_base_url(hub_url)?.origin().ascii_serialization())
    }

    pub(crate) fn endpoint(hub_url: &str, endpoint_path: &str) -> Result<String, ()> {
        let mut url = validated_base_url(hub_url)?;
        url.set_path(endpoint_path);
        Ok(url.to_string())
    }

    fn validated_base_url(hub_url: &str) -> Result<Url, ()> {
        let (_, authority) = hub_url.split_once("://").ok_or(())?;
        if authority.contains('/') || authority.contains('?') || authority.contains('#') {
            return Err(());
        }

        let url = Url::parse(hub_url).map_err(|_| ())?;
        if url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.query().is_some()
            || url.path() != "/"
        {
            return Err(());
        }

        if !matches!(url.scheme(), "http" | "https") {
            return Err(());
        }

        Ok(url)
    }
}
