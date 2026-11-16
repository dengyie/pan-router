package service

import (
	"errors"
	"strings"
	"testing"
)

// TestLogCauseRedactsCredentials 锁住「上游原因可以入日志,但凭据字段必须抹掉」。
// 生产实证(2026-11-17):mangodrive 三次 502 只留下「网络请求失败」这个统一
// 文案,真因(隧道断连)无处可查;补日志的同时不能把 Cookie/token 带进日志文件。
func TestLogCauseRedactsCredentials(t *testing.T) {
	cases := []struct {
		name string
		in   error
		want string
		ban  string
	}{
		{
			name: "查询串 token",
			in:   errors.New(`Post "http://h/api?token=supersecret&x=1": context deadline exceeded`),
			want: "context deadline exceeded",
			ban:  "supersecret",
		},
		{
			name: "Cookie 头",
			in:   errors.New("call failed: Cookie=BDUSS=abcdef; STOKEN=deadbeef"),
			want: "Cookie=***",
			ban:  "deadbeef",
		},
		{
			name: "Authorization 头",
			in:   errors.New("401 Authorization=Bearer abcdefghijklmnop"),
			want: "Authorization=***",
			ban:  "abcdefghijklmnop",
		},
		{
			name: "普通传输错误原样保留",
			in:   errors.New(`Post "http://10.144.144.3:5244/api/fs/get": EOF`),
			want: "10.144.144.3:5244",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := logCause(c.in)
			if !strings.Contains(got, c.want) {
				t.Fatalf("logCause=%q, want contains %q", got, c.want)
			}
			if c.ban != "" && strings.Contains(got, c.ban) {
				t.Fatalf("凭据泄漏到日志: %q", got)
			}
		})
	}
}

// TestLogCauseTruncates:超长错误(异常响应体/整页 HTML)不能整段进日志。
func TestLogCauseTruncates(t *testing.T) {
	got := logCause(errors.New(strings.Repeat("错", logCauseLimit+50)))
	if n := len([]rune(got)); n > logCauseLimit+1 {
		t.Fatalf("未截断: %d runes", n)
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("截断后应带省略号: %q", got)
	}
}

func TestLogCauseNil(t *testing.T) {
	if got := logCause(nil); got != "" {
		t.Fatalf("nil 应返回空串, got %q", got)
	}
}
