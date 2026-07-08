"""Kubernetes Cluster Security Audit Tools - RBAC, pod security, exposed services."""

import logging
from typing import Optional
from langchain_core.tools import tool

logger = logging.getLogger(__name__)


def _get_k8s_client():
    """Load Kubernetes configuration and return CoreV1Api client."""
    try:
        from kubernetes import client, config
    except ImportError:
        raise RuntimeError("kubernetes is required: pip install kubernetes")

    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()

    return client


@tool
def k8s_rbac_audit(namespace: Optional[str] = None) -> str:
    """Audit Kubernetes RBAC for overly permissive roles and bindings.

    Args:
        namespace: Specific namespace to audit. If None, audits cluster-wide.

    Returns:
        List of RBAC misconfigurations including wildcard permissions and cluster-admin bindings.
    """
    try:
        k8s = _get_k8s_client()
        rbac_api = k8s.RbacAuthorizationV1Api()

        issues = []

        # Check ClusterRoleBindings for cluster-admin
        crbs = rbac_api.list_cluster_role_binding()
        for crb in crbs.items:
            if crb.role_ref.name == "cluster-admin":
                subjects = crb.subjects or []
                for s in subjects:
                    if s.kind == "ServiceAccount" and s.namespace != "kube-system":
                        issues.append(
                            f"[HIGH] ServiceAccount '{s.name}' in namespace '{s.namespace}' "
                            f"has cluster-admin via ClusterRoleBinding '{crb.metadata.name}'"
                        )

        # Check for wildcard permissions in ClusterRoles
        crs = rbac_api.list_cluster_role()
        for cr in crs.items:
            if cr.metadata.name.startswith("system:"):
                continue
            for rule in (cr.rules or []):
                resources = rule.resources or []
                verbs = rule.verbs or []
                if "*" in resources or "*" in verbs:
                    issues.append(
                        f"[MEDIUM] ClusterRole '{cr.metadata.name}' has wildcard "
                        f"permissions: resources={resources}, verbs={verbs}"
                    )

        # Check namespace-scoped roles if specified
        if namespace:
            roles = rbac_api.list_namespaced_role(namespace)
            for role in roles.items:
                for rule in (role.rules or []):
                    if "*" in (rule.verbs or []):
                        issues.append(
                            f"[MEDIUM] Role '{role.metadata.name}' in '{namespace}' "
                            f"has wildcard verbs on {rule.resources}"
                        )

        if not issues:
            scope = f"namespace '{namespace}'" if namespace else "cluster-wide"
            return f"RBAC audit ({scope}): No significant issues found."

        header = f"RBAC Audit Results: {len(issues)} issues\n{'='*50}\n"
        return header + "\n".join(issues)

    except Exception as e:
        return f"Error performing RBAC audit: {str(e)}"


@tool
def k8s_pod_security_audit(namespace: str = "default") -> str:
    """Audit pods in a namespace for security misconfigurations.

    Args:
        namespace: Kubernetes namespace to audit.

    Returns:
        List of pod security issues (privileged containers, root users, missing limits, etc.).
    """
    try:
        k8s = _get_k8s_client()
        v1 = k8s.CoreV1Api()

        pods = v1.list_namespaced_pod(namespace)
        issues = []

        for pod in pods.items:
            pod_name = pod.metadata.name
            for container in (pod.spec.containers or []):
                ctx = container.security_context

                # Privileged container
                if ctx and ctx.privileged:
                    issues.append(
                        f"[CRITICAL] Pod '{pod_name}' container '{container.name}' "
                        f"runs as privileged"
                    )

                # Running as root
                if ctx and ctx.run_as_user == 0:
                    issues.append(
                        f"[HIGH] Pod '{pod_name}' container '{container.name}' "
                        f"runs as root (UID 0)"
                    )

                # No run_as_non_root
                if not ctx or not ctx.run_as_non_root:
                    issues.append(
                        f"[MEDIUM] Pod '{pod_name}' container '{container.name}' "
                        f"does not enforce runAsNonRoot"
                    )

                # Missing resource limits
                if not container.resources or not container.resources.limits:
                    issues.append(
                        f"[MEDIUM] Pod '{pod_name}' container '{container.name}' "
                        f"has no resource limits defined"
                    )

                # Host network
                if pod.spec.host_network:
                    issues.append(
                        f"[HIGH] Pod '{pod_name}' uses host network"
                    )

                # Writable root filesystem
                if ctx and not ctx.read_only_root_filesystem:
                    issues.append(
                        f"[LOW] Pod '{pod_name}' container '{container.name}' "
                        f"has writable root filesystem"
                    )

        if not issues:
            return f"Pod security audit for namespace '{namespace}': No issues found."

        header = f"Pod Security Audit [{namespace}]: {len(issues)} issues\n{'='*50}\n"
        return header + "\n".join(issues)

    except Exception as e:
        return f"Error performing pod security audit: {str(e)}"


@tool
def k8s_exposed_services(namespace: Optional[str] = None) -> str:
    """Find Kubernetes services exposed externally (LoadBalancer, NodePort).

    Args:
        namespace: Namespace to check. If None, checks all namespaces.

    Returns:
        List of externally exposed services with ports and potential risks.
    """
    try:
        k8s = _get_k8s_client()
        v1 = k8s.CoreV1Api()

        if namespace:
            services = v1.list_namespaced_service(namespace)
        else:
            services = v1.list_service_for_all_namespaces()

        exposed = []
        for svc in services.items:
            svc_type = svc.spec.type
            if svc_type in ("LoadBalancer", "NodePort"):
                ports = []
                for port in (svc.spec.ports or []):
                    port_info = f"{port.port}"
                    if port.node_port:
                        port_info += f" (NodePort: {port.node_port})"
                    ports.append(port_info)

                external_ip = "Pending"
                if svc.status.load_balancer and svc.status.load_balancer.ingress:
                    ing = svc.status.load_balancer.ingress[0]
                    external_ip = ing.ip or ing.hostname or "Pending"

                risk = "HIGH" if svc_type == "LoadBalancer" else "MEDIUM"
                exposed.append(
                    f"[{risk}] {svc.metadata.namespace}/{svc.metadata.name}\n"
                    f"  Type: {svc_type}\n"
                    f"  External IP: {external_ip}\n"
                    f"  Ports: {', '.join(ports)}\n"
                )

        if not exposed:
            scope = f"namespace '{namespace}'" if namespace else "all namespaces"
            return f"No externally exposed services found in {scope}."

        header = f"Exposed Services: {len(exposed)} found\n{'='*50}\n"
        return header + "\n".join(exposed)

    except Exception as e:
        return f"Error checking exposed services: {str(e)}"


@tool
def k8s_image_vulnerability_check(namespace: str = "default") -> str:
    """List container images running in a namespace for vulnerability assessment.

    Args:
        namespace: Kubernetes namespace to inspect.

    Returns:
        List of container images with their tags, highlighting those using 'latest' or no tag.
    """
    try:
        k8s = _get_k8s_client()
        v1 = k8s.CoreV1Api()

        pods = v1.list_namespaced_pod(namespace)
        images = {}
        issues = []

        for pod in pods.items:
            for container in (pod.spec.containers or []):
                img = container.image
                if img not in images:
                    images[img] = []
                images[img].append(f"{pod.metadata.name}/{container.name}")

                if ":latest" in img or ":" not in img:
                    issues.append(
                        f"[HIGH] Image '{img}' uses 'latest' or no tag "
                        f"(pod: {pod.metadata.name})"
                    )

        lines = [
            f"Image Audit [{namespace}]: {len(images)} unique images, {len(issues)} issues",
            "=" * 50,
        ]

        if issues:
            lines.append("\nIssues:")
            lines.extend(f"  {i}" for i in issues)

        lines.append(f"\nAll images ({len(images)}):")
        for img, pods_list in sorted(images.items()):
            lines.append(f"  {img} (used by {len(pods_list)} container(s))")

        return "\n".join(lines)

    except Exception as e:
        return f"Error checking images: {str(e)}"
