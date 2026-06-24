pub mod cli;
pub mod collectors;
pub mod host_profile;
pub mod metrics;
pub mod privileged_collectors;
pub mod privileged_runtime;
pub mod probe_auth;
pub mod protocol;
pub mod registration;
pub mod report;
pub mod runtime;
pub mod upgrader;
pub mod version;

pub(crate) mod hub_url {
    use url::Url;

    pub(crate) fn normalized_base(hub_url: &str) -> Result<String, ()> {
        let mut url = validated_base_url(hub_url)?;
        let base_path = url.path().trim_end_matches('/').to_string();
        url.set_path(&base_path);
        let mut normalized = url.to_string();
        if normalized.ends_with('/') {
            normalized.pop();
        }
        Ok(normalized)
    }

    pub(crate) fn endpoint(hub_url: &str, endpoint_path: &str) -> Result<String, ()> {
        let mut url = validated_base_url(hub_url)?;
        let base_path = url.path().trim_end_matches('/');
        let endpoint_path = endpoint_path.trim_start_matches('/');
        url.set_path(&format!("{base_path}/{endpoint_path}"));
        Ok(url.to_string())
    }

    fn validated_base_url(hub_url: &str) -> Result<Url, ()> {
        let mut url = Url::parse(hub_url).map_err(|_| ())?;
        if url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.query().is_some()
        {
            return Err(());
        }

        match url.scheme() {
            "https" => {}
            "http" if is_local_development_host(&url) => {}
            _ => return Err(()),
        }

        url.set_fragment(None);
        Ok(url)
    }

    fn is_local_development_host(url: &Url) -> bool {
        matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"))
    }
}
