from src.ngfw_engine import IdentityContext, NGFWEngine, Packet


def run_demo() -> None:
    engine = NGFWEngine()
    engine.intel.update_from_iocs(
        ja3_hashes={"deadbeef001122334455"},
        ips={"203.0.113.66"},
        ports={31337},
    )

    packet = Packet(
        src_ip="10.1.2.20",
        dst_ip="203.0.113.66",
        dst_port=4444,
        protocol="QUIC",
        bytes_out=2_500_000,
        tls_version="TLS1.2",
        ja3_hash="deadbeef001122334455",
        user_id="alice",
        device_id="laptop-01",
    )

    identity = IdentityContext(
        user_id="alice",
        device_id="laptop-01",
        user_trust=0.55,
        device_trust=0.6,
        mfa_verified=False,
        geo_velocity_risky=True,
    )

    result = engine.evaluate_packet(packet, identity)
    actions = engine.soar_actions(result.decision)

    print("Decision:", result.decision)
    print("Explanation:", result.explanation)
    print("SOAR Actions:", ", ".join(actions))


if __name__ == "__main__":
    run_demo()
