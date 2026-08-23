#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatteryMetrics {
    pub percent: u32,
    pub state: String,
}
