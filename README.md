# k8s-guardian

Autonomous Kubernetes guardian service that performs health checks, log triage, and controlled remediation decisions.

## Highlights

- Two-tier triage/decision flow for log analysis and issue escalation
- Cluster health polling with optional remediation hooks
- Lightweight service intended to sit close to live cluster operations

## Tech Stack

- Python, FastAPI, subprocess-based cluster introspection, HTTP integrations

## Repository Layout

- `app.py`
- `requirements.txt`
- `Dockerfile`

## Getting Started

- Install dependencies from `requirements.txt` or build the Docker image.
- Set your model and cluster environment variables before starting the service.
- Run the service locally with `python app.py` or containerize it for cluster-adjacent deployment.

## Current Status

- This README was refreshed from a code audit and is intentionally scoped to what is directly visible in the repository.
