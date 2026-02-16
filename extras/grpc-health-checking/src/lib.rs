// hide generated values in private module (volo-generated code)
#[allow(clippy::clone_on_ref_ptr, clippy::single_match_else)]
mod generator {
    include!(concat!(env!("OUT_DIR"), "/proto_gen.rs"));
}

use crate::grpc::health::v1::health_check_response::ServingStatus;
use crate::grpc::health::v1::{Health, HealthCheckRequest, HealthCheckResponse};
use futures::stream::BoxStream;
pub use generator::proto_gen::*;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use volo_grpc::{Request, Response, Status};

pub trait HealthStatus {
    fn name(&self) -> &str;
    fn is_serving(&self) -> bool;
}

#[derive(Default)]
pub struct HealthRegistry {
    services: Vec<Arc<dyn HealthStatus + Send + Sync>>,
}

impl HealthRegistry {
    pub fn new() -> Self {
        HealthRegistry { services: vec![] }
    }

    pub fn register(&mut self, service: Arc<dyn HealthStatus + Send + Sync>) {
        self.services.push(service);
    }
}

impl Health for HealthRegistry {
    async fn check(
        &self,
        req: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        let service_name = req.into_inner().service;

        let result = self
            .services
            .iter()
            .filter(|s| s.name() == service_name)
            .map(|s| {
                if s.is_serving() {
                    Ok(Response::new(HealthCheckResponse {
                        status: ServingStatus::SERVING,
                        _unknown_fields: Default::default(),
                    }))
                } else {
                    Ok(Response::new(HealthCheckResponse {
                        status: ServingStatus::NOT_SERVING,
                        _unknown_fields: Default::default(),
                    }))
                }
            })
            .next_back();

        result.ok_or(Status::not_found("Service not found"))?
    }

    async fn watch(
        &self,
        req: Request<HealthCheckRequest>,
    ) -> Result<Response<BoxStream<'static, Result<HealthCheckResponse, Status>>>, Status> {
        let request = req.into_inner();
        let service_name = request.service;

        let service = self
            .services
            .iter()
            .find(|s| s.name() == service_name)
            .ok_or(Status::not_found("Service not found"))?;

        let (tx, rx) = mpsc::channel(16);

        let service = Arc::clone(service);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
            loop {
                interval.tick().await;
                let service_status = service.is_serving();
                let resp = if service_status {
                    HealthCheckResponse {
                        status: ServingStatus::SERVING,
                        _unknown_fields: Default::default(),
                    }
                } else {
                    HealthCheckResponse {
                        status: ServingStatus::NOT_SERVING,
                        _unknown_fields: Default::default(),
                    }
                };

                match tx.send(Result::<_, Status>::Ok(resp)).await {
                    Ok(_) => {}
                    Err(_) => {
                        break;
                    }
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}
