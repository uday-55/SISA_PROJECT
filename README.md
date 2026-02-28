# AI-Driven Next-Generation Firewall (NGFW) Prototype

This repository contains a **production-oriented prototype design** for an AI-powered NGFW aligned with your problem statement on dynamic threat detection and Zero Trust.

## What this prototype demonstrates

- **Advanced traffic analytics** for encrypted flows using lightweight feature-based classification.
- **Real-time anomaly detection** via online statistical baselining.
- **Graph-aware lateral movement detection** to identify suspicious east-west behavior.
- **Zero Trust policy decisions** that combine user, device, network, and threat-intel context.
- **Federated intelligence primitives** for privacy-preserving model weight aggregation.
- **SOAR-like automated response** mapping for quarantine, block, and step-up authentication.

## Architecture mapping to the problem statement

| Problem Statement Area | Prototype Component |
|---|---|
| TLS/SSL visibility challenge | `classify_encrypted_flow` feature classifier in `src/ngfw_engine.py` |
| Dynamic IoC / ATT&CK adaptation | `ThreatIntel` ingestion + adaptive risk in `evaluate_packet` |
| Zero Trust enforcement | `IdentityContext` + risk-weighted access decisioning |
| Federated AI | `federated_average` aggregator for distributed updates |
| Automated mitigation | `soar_actions` playbook binding from decision outcome |
| Unified telemetry | `DetectionResult` and generated explanation fields |

## Quickstart

```bash
python -m src.main
```

Run tests:

```bash
python -m unittest discover -s tests -p 'test_*.py'
```

## Notes

- This code is intentionally lightweight and dependency-minimal so it can run in constrained environments.
- The model logic is designed to be replaced by production CNN/transformer/graph ML backends (e.g., TensorFlow/PyTorch + stream processors).
