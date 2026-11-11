package monitor

import "strings"

// NormalizeKind maps aliases (e.g. "prom") onto canonical Kind values.
func NormalizeKind(raw string) Kind {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "prom", string(KindPrometheus):
		return KindPrometheus
	case string(KindGRPC):
		return KindGRPC
	case string(KindHTTPS):
		return KindHTTPS
	case string(KindTCP):
		return KindTCP
	case string(KindICMP):
		return KindICMP
	case string(KindSMTP):
		return KindSMTP
	case string(KindIMAP):
		return KindIMAP
	case string(KindDNS):
		return KindDNS
	case string(KindSDNS):
		return KindSDNS
	case string(KindUDP):
		return KindUDP
	case string(KindWhois):
		return KindWhois
	case string(KindHeartbeat):
		return KindHeartbeat
	default:
		return Kind(strings.ToLower(strings.TrimSpace(raw)))
	}
}
