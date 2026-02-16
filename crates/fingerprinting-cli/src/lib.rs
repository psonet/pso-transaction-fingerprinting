use grpc_health_checking::HealthStatus;

pub mod config;

pub struct HealthRegistryService {
    pub name: String,
}

impl HealthStatus for HealthRegistryService {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn is_serving(&self) -> bool {
        true
    }
}
