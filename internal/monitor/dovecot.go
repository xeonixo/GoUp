package monitor

import (
	"context"
	"strings"
)

type DovecotChecker struct{}

func (c DovecotChecker) Check(ctx context.Context, item Monitor) Result {
	result := IMAPChecker{}.Check(ctx, item)
	replacer := strings.NewReplacer(
		"IMAP", "Dovecot",
		"imap", "dovecot",
	)
	result.Message = replacer.Replace(result.Message)
	return result
}
