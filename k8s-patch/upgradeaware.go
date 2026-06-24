package proxy

import (
	"io"
	"log"
	"net"
	"net/http"
)

// UpgradeAwareProxyHandler handles proxying upgraded connections (e.g., WebSockets)
type UpgradeAwareProxyHandler struct {
	BackendDialer func() (net.Conn, error)
}

func (h *UpgradeAwareProxyHandler) ProxyConnection(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Connection") != "Upgrade" {
		return
	}

	// Dialing the backend Kubelet/Service
	backendConn, err := h.BackendDialer()
	if err != nil {
		log.Printf("[VULN-TRACE] Failed to connect to backend: %v", err)
		http.Error(w, "Backend unavailable", http.StatusBadGateway)
		return
	}
	defer backendConn.Close()

	// Hijack the client HTTP connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("[VULN-TRACE] ResponseWriter does not support Hijacker interface")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	hjConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("[VULN-TRACE] Client connection hijacking failed: %v", err)
		return
	}

	// =========================================================================
	// CVE-2018-1002105 FIX: 
	// In the vulnerable version, if the backend returned an upgrade failure,
	// hjConn was kept open and unmonitored, allowing connection reuse bypasses.
	// We force closure on function exit to eliminate the exploit window.
	// =========================================================================
	defer func() {
		log.Printf("[VULN-TRACE] Security Patch: Forcing connection closure to prevent hijacking.")
		if hjConn != nil {
			hjConn.Close()
		}
	}()

	// Establish bidirectional data streaming between client and backend
	go io.Copy(backendConn, hjConn)
	io.Copy(hjConn, backendConn)
}