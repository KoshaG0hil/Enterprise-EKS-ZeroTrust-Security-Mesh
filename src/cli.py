"""Enterprise EKS Zero-Trust Security Mesh Operator CLI."""

import argparse
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.core.config import ClusterAuditResult, PodContext, PodStatus, Severity
from src.reporters.compliance_manifest import ComplianceManifestGenerator
from src.runtime.falco_alert_processor import FalcoAlertProcessor
from src.runtime.pod_isolation_controller import PodIsolationController
from src.scanners.ebpf_network_auditor import EBPFNetworkAuditor
from src.scanners.gatekeeper_auditor import GatekeeperAuditor

console = Console()

BANNER = r"""[bold cyan]
    ________ __ _____   _____                      __           __  ___          __
   / ____/ //_// ___/  / ___/___  _______  _______/ /___  __   /  |/  /__  _____/ /_
  / __/ / ,<   \__ \   \__ \/ _ \/ ___/ / / / ___/ __/ / / /  / /|_/ / _ \/ ___/ __ \
 / /___/ /| | ___/ /  ___/ /  __/ /__/ /_/ / /  / /_/ /_/ /  / /  / /  __(__  ) / / /
/_____/_/ |_|/____/  /____/\___/\___/\__,_/_/   \__/\__, /  /_/  /_/\___/____/_/ /_/
                                                   /____/
[/bold cyan]
[dim]Enterprise Kubernetes (EKS) Zero-Trust Container Runtime Security & eBPF Threat Mesh[/dim]
"""


def get_demo_cluster_pods() -> list[PodContext]:
    """Returns realistic mock pods across production, staging, and workloads namespaces."""
    return [
        PodContext(
            name="payment-gateway-7f9a-110",
            namespace="production",
            labels={"app": "payment-gateway", "tier": "frontend"},
            privileged=False,
            readonly_root_fs=True,
            run_as_non_root=True,
            has_cilium_policy=True,
            status=PodStatus.HEALTHY,
        ),
        PodContext(
            name="auth-vault-token-55ab-204",
            namespace="production",
            labels={"app": "auth-service", "tier": "backend"},
            privileged=False,
            readonly_root_fs=True,
            run_as_non_root=True,
            has_cilium_policy=True,
            status=PodStatus.HEALTHY,
        ),
        PodContext(
            name="legacy-report-worker-33d8-301",
            namespace="production",
            labels={"app": "legacy-worker"},
            privileged=True,  # VIOLATION: Privileged mode
            readonly_root_fs=False,  # VIOLATION: Writable rootfs
            run_as_non_root=False,  # VIOLATION: Root user
            hostpath_mounts=["/var/run/docker.sock"],  # VIOLATION: HostPath
            has_cilium_policy=True,
            status=PodStatus.VIOLATION_DETECTED,
        ),
        PodContext(
            name="analytics-collector-88c1-409",
            namespace="staging",
            labels={"app": "analytics"},
            privileged=False,
            readonly_root_fs=True,
            run_as_non_root=True,
            has_cilium_policy=False,  # VIOLATION: Missing Cilium eBPF policy
            status=PodStatus.VIOLATION_DETECTED,
        ),
        PodContext(
            name="compromised-web-frontend-99f2",
            namespace="production",
            labels={"app": "web-frontend"},
            privileged=False,
            readonly_root_fs=True,
            run_as_non_root=True,
            has_cilium_policy=True,
            status=PodStatus.HEALTHY,
        ),
    ]


def cmd_audit(args):
    """Audits cluster pods against OPA Gatekeeper constraints and eBPF policies."""
    console.print(BANNER)
    pods = get_demo_cluster_pods()
    gk_auditor = GatekeeperAuditor()
    ebpf_auditor = EBPFNetworkAuditor()

    gk_violations = gk_auditor.audit_cluster(pods)
    ebpf_violations = ebpf_auditor.audit_cluster_network(pods)

    total_violations = len(gk_violations) + len(ebpf_violations)
    score = ComplianceManifestGenerator.calculate_score(pods, total_violations)

    table = Table(title="[EKS Zero-Trust Static & Network Audit]", show_header=True, header_style="bold cyan")
    table.add_column("Pod Name", style="white", width=34)
    table.add_column("Namespace", style="dim", width=14)
    table.add_column("Rule / Policy", style="yellow", width=32)
    table.add_column("Severity", style="bold", width=12)
    table.add_column("Status", style="bold", width=16)

    for v in gk_violations:
        sev_color = "red" if v.severity == Severity.CRITICAL else "yellow"
        table.add_row(
            v.pod_name,
            v.namespace,
            v.constraint_name,
            f"[{sev_color}]{v.severity.value}[/{sev_color}]",
            "[red]GATEKEEPER_BLOCK[/red]",
        )

    for nv in ebpf_violations:
        table.add_row(
            nv.pod_name,
            nv.namespace,
            "Cilium Zero-Trust eBPF",
            f"[yellow]{nv.severity.value}[/yellow]",
            "[yellow]UNPROTECTED[/yellow]",
        )

    console.print(table)
    console.print(f"\n[bold green]Cluster Compliance Rating:[/bold green] [bold cyan]{score}%[/bold cyan]\n")


def cmd_simulate(args):
    """Executes full end-to-end zero-trust attack simulation and autonomous pod quarantine."""
    console.print(BANNER)
    console.print(
        Panel(
            "[bold yellow]Initiating EKS Zero-Trust Threat Simulation & Autonomous Quarantine[/bold yellow]\n"
            "[dim]Target: EKS Cluster prod-eks-zero-trust-mesh (1.30)[/dim]\n"
            "[dim]Vectors: OPA Gatekeeper Admission, Cilium eBPF L7 Filter, Falco Runtime Shell Injection[/dim]",
            title="[Simulation Harness]",
            border_style="cyan",
        )
    )

    pods = get_demo_cluster_pods()
    gk_auditor = GatekeeperAuditor()
    ebpf_auditor = EBPFNetworkAuditor()
    isolation_ctrl = PodIsolationController(dry_run=True)
    reporter = ComplianceManifestGenerator()

    # Step 1: Static Policy Evaluation
    console.print("[1/4] [bold cyan]Evaluating OPA Gatekeeper Admission & eBPF Policy Coverage...[/bold cyan]")
    gk_violations = gk_auditor.audit_cluster(pods)
    ebpf_violations = ebpf_auditor.audit_cluster_network(pods)
    console.print(f"      [green][+][/green] Detected {len(gk_violations)} admission constraint violations.")
    console.print(f"      [green][+][/green] Detected {len(ebpf_violations)} unprotected eBPF network endpoints.")

    # Step 2: Runtime Threat Injection via Falco
    console.print(
        "\n[2/4] [bold red]Injecting Runtime Adversary Event on Pod 'compromised-web-frontend-99f2'...[/bold red]"
    )
    falco_payload = {
        "rule": "Terminal Shell Spawned in Container",
        "priority": "CRITICAL",
        "output_fields": {
            "k8s.pod.name": "compromised-web-frontend-99f2",
            "k8s.ns.name": "production",
            "container.id": "containerd://98fa012b",
        },
        "output": "CRITICAL: Interactive /bin/sh spawned by unauthorized user inside web-frontend container.",
        "time": "2026-10-29T10:05:00Z",
    }
    alert = FalcoAlertProcessor.parse_alert_payload(falco_payload)
    console.print(f"      [bold red]ALERT TRIGGERED:[/bold red] {alert.rule_name} (Priority: {alert.priority.value})")

    # Step 3: Autonomous Pod Quarantine
    console.print("\n[3/4] [bold yellow]Executing Autonomous Zero-Trust Pod Quarantine...[/bold yellow]")
    compromised_pod = pods[4]
    action = isolation_ctrl.quarantine_pod(compromised_pod, reason=alert.rule_name)
    console.print("      [green][+][/green] Applied quarantine label: security.mesh/quarantine=isolated")
    console.print(f"      [green][+][/green] Injected Cilium eBPF drop-all network policy: {action.policy_attached}")
    console.print("      [green][+][/green] Preserved memory and disk state for SecOps forensic investigation.")

    # Step 4: Compliance Manifest
    console.print("\n[4/4] [bold green]Generating Signed Audit Manifest...[/bold green]")
    compliant_pods = len([p for p in pods if p.status == PodStatus.HEALTHY])
    total_violations = len(gk_violations) + len(ebpf_violations)
    score = reporter.calculate_score(pods, total_violations)

    audit_result = ClusterAuditResult(
        total_evaluated_pods=len(pods),
        compliant_pods=compliant_pods,
        gatekeeper_violations=gk_violations,
        network_violations=ebpf_violations,
        quarantined_pods=1,
        compliance_score=score,
    )

    manifest = reporter.generate(audit_result, pods)
    out_file = reporter.save_report(manifest)

    console.print(
        Panel(
            f"[bold green]Overall Compliance Rating:[/bold green] {score}%\n"
            f"[bold white]Total Evaluated Pods:[/bold white]     {len(pods)}\n"
            f"[bold green]Compliant Active Pods:[/bold green]    {compliant_pods}\n"
            f"[bold yellow]Gatekeeper Violations:[/bold yellow]   {len(gk_violations)}\n"
            f"[bold red]Quarantined Pods:[/bold red]        1 (Isolated at eBPF layer)\n"
            f"[bold cyan]Cryptographic SHA-256:[/bold cyan]   {manifest['sha256_checksum']}\n"
            f"[bold dim]Audit Manifest Saved:[/bold dim]    {out_file}",
            title="[Executive Cluster Security Posture]",
            border_style="green",
        )
    )


def main():
    parser = argparse.ArgumentParser(description="Enterprise EKS Zero-Trust Security Mesh CLI")
    subparsers = parser.add_subparsers(dest="command")

    # audit-cluster
    audit_parser = subparsers.add_parser("audit-cluster", help="Audits cluster for Gatekeeper and eBPF compliance")
    audit_parser.set_defaults(func=cmd_audit)

    # simulate
    sim_parser = subparsers.add_parser("simulate", help="Runs full attack simulation and autonomous pod quarantine")
    sim_parser.set_defaults(func=cmd_simulate)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
