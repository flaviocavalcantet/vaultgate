# ADR 0001: Tornado for the data plane, FastAPI for the control plane

**Status:** Accepted

## Context

VaultGate handles two very different kinds of traffic:

1. **Control requests**: log in, create a share link, edit a policy, list files.
   Small JSON bodies, many endpoints, schemas that should be validated and documented.
2. **File transfers**: uploads and downloads that can reach several gigabytes.

Using one framework for both would work, but each kind of traffic has a framework that fits it better.

## Decision

- **FastAPI** serves the control plane. Pydantic models give request validation and an
  OpenAPI spec for free, and dependency injection keeps auth and policy checks out of handlers.
- **Tornado** serves the data plane. `@stream_request_body` delivers an upload chunk by chunk
  as it arrives, so each chunk can be encrypted and forwarded to storage without buffering
  the whole body. Memory per connection stays constant regardless of file size.

The gateway never decides who may do what. Before accepting bytes it asks the API to validate
a short-lived, single-use upload intent, so authorization lives in one place.

## Consequences

- Two Python services to build, test and deploy instead of one.
- Clear scaling boundary: the gateway scales on concurrent connections and bandwidth,
  the API on request rate.
- A slow or huge upload can never starve control-plane requests, because they run in different processes.
