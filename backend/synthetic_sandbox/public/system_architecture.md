# System Architecture
Microservices communicate via gRPC over internal mesh.
Public APIs expose read-only catalog data at https://api.internal.mock/v1/catalog.
Authentication is governed by zero-trust identity brokers.