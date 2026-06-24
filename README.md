\# Kubernetes Runtime Security \& CVE-2018-1002105 Analysis



A hands-on security research project focused on container runtime protection using \*\*Falco (eBPF)\*\* and low-level source-code analysis/patching of the \*\*CVE-2018-1002105\*\* vulnerability inside the Kubernetes API server network proxy layer.



\##  Tech Stack \& Tools

\* \*\*Languages:\*\* Go (Golang), YAML

\* \*\*Security Frameworks:\*\* Falco (`modern\\\\\\\\\\\\\\\_bpf` kernel probe)

\* \*\*Infrastructure:\*\* Kubernetes, Docker/Containerd

\* \*\*Protocols \& Concepts:\*\* TCP/IP Socket Hijacking, Reverse Shells, Syscall Auditing (`execve`, `openat`), RBAC Bypass



\---



\##  Project Overview



This project layout demonstrates a two-way approach to Kubernetes security:

1\. \*\*Defensive Layer (Runtime):\*\* Utilizing eBPF to monitor system calls at the kernel level to detect post-exploitation behavior (reverse shells, unauthorized file access).

2\. \*\*Vulnerability Research (Deep Dive):\*\* Reproducing and patching a critical privilege escalation flaw inside `kube-apiserver` by tracking TCP connection upgrade lifecycles.



\---



\##  1. CVE-2018-1002105: Connection Hijack \& Patching



\### Vulnerability Mechanism

The flaw lies in how the Kubernetes API server handles aggregated APIs and WebSocket/SPDY connection upgrades. When a client requests a connection upgrade (e.g., `kubectl exec`), the API server proxies the request to the backend Kubelet.

If the backend rejects the upgrade, the `kube-apiserver` fails to properly intercept the failure and leaves the TCP socket open, allowing the attacker to reuse the established high-privilege connection to send arbitrary commands directly to the backend API bypasssing RBAC verification.



\### Implementation \& Fix

In `k8s-patch/upgradeaware.go`, the core networking logic was audited:

\* Added custom inline tracing labeled `\\\\\\\\\\\\\\\[VULN-TRACE]` to monitor the lifecycle of the hijacked connection (`hjConn`).

\* Implemented an explicit source-code fix forcing the connection to close immediately upon backend handshake failure, mitigating the reuse vector:



```go

// Custom security patch applied inside the upgrade proxy loop

if err != nil {

\\\\\\\&#x20;   log.Printf("\\\\\\\\\\\\\\\[VULN-TRACE] Backend upgrade failed. Forcing connection closure to prevent hijacking.")

\\\\\\\&#x20;   if hjConn != nil {

\\\\\\\&#x20;       hjConn.Close() // Explicitly close user-to-proxy connection

\\\\\\\&#x20;   }

\\\\\\\&#x20;   return

}




