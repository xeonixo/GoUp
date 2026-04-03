package monitor

import (
	"context"
	"fmt"
	"net"
	"time"
)

type TCPChecker struct{}

func (c TCPChecker) Check(ctx context.Context, item Monitor) Result {
	startedAt := time.Now()
	result := Result{
		MonitorID: item.ID,
		CheckedAt: startedAt.UTC(),
		Status:    StatusDown,
	}

	dialer := &net.Dialer{Timeout: item.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", item.Target)
	result.Latency = time.Since(startedAt)
	if err != nil {
		result.Message = fmt.Sprintf("tcp connect failed: %v", err)
		return result
	}
	_ = conn.Close()

	result.Status = StatusUp
	result.Message = fmt.Sprintf("TCP connect ok in %d ms", result.Latency.Milliseconds())
	return result
}
