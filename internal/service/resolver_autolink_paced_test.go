package service

// v2.16.2 回归:自动提链不得把「我方本地准入拒绝」当终态。
//
// 现场(2026-11-17,百度 8 文件加密分享):只有 1 个文件真正打到上游,
// 其余 7 个全是「本地限频:请求过于频繁,请稍后」
// (panrouter_local_throttle_total{pan="baidu",reason="rate_limit"} 7),
// 而 slow resolve 日志却报 linked=8 —— 那个计数在**尝试前**自增,把尝试当成成功。
//
// 本地令牌桶 capacity == rate 且 Allow 非阻塞:一次批量提链几百毫秒内就能把桶
// 打空。闸门的职责是放慢我们自己发起的批量提链,不是让用户的一次解析部分失败。

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dengyie/panrouter/internal/config"
	"github.com/dengyie/panrouter/internal/driver"
)

// linked 只统计真正拿到直链的文件。
func TestAutoLinkLinkedCountsSuccessOnly(t *testing.T) {
	d := &twoFileDriver{fn: func(context.Context, string) (driver.DirectLink, error) {
		return driver.DirectLink{}, driver.NewErr(driver.KindUpstream, "上游 500", nil)
	}}
	resolver, _ := newTestResolver(t, d, config.DriverCommon{Enabled: true, LimitQPS: 1000, DownloadConc: 3})

	items := []FileItem{{FID: "f1", Name: "a.bin"}, {FID: "f2", Name: "b.bin"}}
	nodes := []driver.FileNode{{FID: "f1", Name: "a.bin"}, {FID: "f2", Name: "b.bin"}}
	pending := []int{0, 1}

	linked, _, _, _ := resolver.autoLinkSerial(context.Background(), testShareURL, "", nodes, items, pending, "", "fake")
	if linked != 0 {
		t.Fatalf("全部失败时 linked 必须为 0, got %d(旧实现返回尝试数 2)", linked)
	}
	// 并行版同型:计数只在成功分支自增。
	items2 := []FileItem{{FID: "f1", Name: "a.bin"}, {FID: "f2", Name: "b.bin"}}
	d2 := &twoFileDriver{fn: func(context.Context, string) (driver.DirectLink, error) {
		return driver.DirectLink{}, driver.NewErr(driver.KindUpstream, "上游 500", nil)
	}}
	resolver2, _ := newTestResolver(t, d2, config.DriverCommon{Enabled: true, LimitQPS: 1000, DownloadConc: 3})
	linked2, _, _, _ := resolver2.autoLinkParallel(context.Background(), testShareURL, "", nodes, items2, pending, 2, "", "fake")
	if linked2 != 0 {
		t.Fatalf("并行版:全部失败时 linked 必须为 0, got %d", linked2)
	}

	// 全部成功时计数等于成功数。
	d3 := &twoFileDriver{}
	resolver3, _ := newTestResolver(t, d3, config.DriverCommon{Enabled: true, LimitQPS: 1000, DownloadConc: 3})
	items3 := []FileItem{{FID: "f1", Name: "a.bin"}, {FID: "f2", Name: "b.bin"}}
	linked3, _, _, _ := resolver3.autoLinkSerial(context.Background(), testShareURL, "", nodes, items3, pending, "", "fake")
	if linked3 != 2 {
		t.Fatalf("全部成功时 linked 应为 2, got %d", linked3)
	}
}

// 令牌桶被打空后,批量提链必须退避重试把整批放完,而不是直接判失败。
func TestAutoLinkRetriesLocalThrottle(t *testing.T) {
	d := &twoFileDriver{}
	// 20 QPS:容量 20,补一个令牌 50ms;本地步进夹到 100ms,测试窗口内可恢复。
	dc := config.DriverCommon{Enabled: true, LimitQPS: 20, DownloadConc: 3}
	resolver, _ := newTestResolver(t, d, dc)
	// 先全部取走,模拟「并发请求先到,桶已空」。
	for i := 0; i < 20; i++ {
		if !resolver.limiter.Allow("fake", dc.LimitQPS) {
			t.Fatalf("第 %d 个初始令牌应可用", i)
		}
	}

	res, err := resolver.ResolveShare(WithAuthed(context.Background(), true), testShareURL, "", "")
	if err == nil {
		t.Fatalf("桶空时 ResolveShare 的列表准入也应拒绝(对外 429 语义), got %+v", res)
	}
	// 列表准入拒绝属于「客户端该退避」的外部契约,不在这里改;这里验证的是
	// 列表已经拿到之后的批量提链:桶空必须退避重试,而不是整批判失败。
	items := []FileItem{{FID: "f1", Name: "a.bin"}, {FID: "f2", Name: "b.bin"}}
	nodes := []driver.FileNode{{FID: "f1", Name: "a.bin"}, {FID: "f2", Name: "b.bin"}}
	linked, _, _, hint := resolver.autoLinkSerial(WithAuthed(context.Background(), true),
		testShareURL, "", nodes, items, []int{0, 1}, "", "fake")
	if linked != 2 {
		t.Fatalf("桶空时批量提链应退避重试后全部成功, linked=%d hint=%q items=%+v", linked, hint, items)
	}
	for _, it := range items {
		if it.LinkError != "" || it.DownloadURL == "" {
			t.Fatalf("桶空时应退避重试而不是判失败: %+v", it)
		}
	}
	if got := d.calls.Load(); got != 2 {
		t.Fatalf("GetDirectLink 调用次数=%d, 期望 2(重试只在本地拒绝时发生)", got)
	}
	if body := scrapeMetrics(t, resolver.met); !strings.Contains(body, `panrouter_auto_link_retry_total{pan="fake"}`) {
		t.Fatalf("本地限频重试计数缺失: %s", body)
	}
}

// 上游错误不得重试:重试只针对我方准入拒绝,否则会把风控/故障放大。
func TestAutoLinkDoesNotRetryUpstreamError(t *testing.T) {
	d := &twoFileDriver{fn: func(context.Context, string) (driver.DirectLink, error) {
		return driver.DirectLink{}, driver.NewErr(driver.KindUpstream, "上游 500", nil)
	}}
	resolver, _ := newTestResolver(t, d, config.DriverCommon{Enabled: true, LimitQPS: 20, DownloadConc: 3})
	if _, err := resolver.ResolveShare(WithAuthed(context.Background(), true), testShareURL, "", ""); err != nil {
		t.Fatalf("ResolveShare: %v", err)
	}
	if got := d.calls.Load(); got != 2 {
		t.Fatalf("上游错误不应重试: GetDirectLink 调用 %d 次,期望 2(每文件一次)", got)
	}
	if body := scrapeMetrics(t, resolver.met); strings.Contains(body, `panrouter_auto_link_retry_total{pan="fake"}`) {
		t.Fatalf("上游错误不应计入本地重试: %s", body)
	}
}

// 本地步进间隔 = 1/limit_qps,夹在 [100ms, 2s]。
func TestLocalPaceInterval(t *testing.T) {
	cases := []struct {
		qps  float64
		want time.Duration
	}{
		{0, 100 * time.Millisecond},
		{0.01, 2 * time.Second},
		{2, 500 * time.Millisecond},
		{1000, 100 * time.Millisecond},
	}
	for _, c := range cases {
		resolver, _ := newTestResolver(t, &twoFileDriver{},
			config.DriverCommon{Enabled: true, LimitQPS: c.qps, DownloadConc: 3})
		if got := resolver.localPaceInterval("fake"); got != c.want {
			t.Fatalf("qps=%v: got %v want %v", c.qps, got, c.want)
		}
	}
}

// asLocalThrottle 只认我方准入包装,不认上游 risk_control。
func TestAsLocalThrottle(t *testing.T) {
	local := &errLocalThrottle{driver.NewErr(driver.KindRiskControl, "本地限频", nil)}
	if !asLocalThrottle(local) {
		t.Fatal("errLocalThrottle 必须被识别")
	}
	if asLocalThrottle(driver.NewErr(driver.KindRiskControl, "上游风控", nil)) {
		t.Fatal("上游 risk_control 不得被当成我方准入")
	}
	if asLocalThrottle(nil) {
		t.Fatal("nil 不是本地准入")
	}
	if !errors.Is(local, local.err) && local.Unwrap() == nil {
		t.Fatal("errLocalThrottle 必须可 Unwrap")
	}
}

// PoolState 只把「冷却未到期」算作冷却;到期/过期/正常都不算。
func TestPoolStateCountsCoolingOnly(t *testing.T) {
	resolver, store := newTestResolver(t, &twoFileDriver{},
		config.DriverCommon{Enabled: true, LimitQPS: 1000, DownloadConc: 3})
	seedCookieAccount(t, store)
	accs, err := store.ListAccounts("fake")
	if err != nil || len(accs) != 1 {
		t.Fatalf("seed account: %v %d", err, len(accs))
	}
	if total, cooling, _, err := resolver.accounts.PoolState("fake"); err != nil || total != 1 || cooling != 0 {
		t.Fatalf("正常账号不应算冷却: total=%d cooling=%d err=%v", total, cooling, err)
	}
	until := time.Now().Add(2 * time.Minute)
	if err := store.MarkAccountCooldown(accs[0].ID, until); err != nil {
		t.Fatal(err)
	}
	total, cooling, ready, err := resolver.accounts.PoolState("fake")
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || cooling != 1 {
		t.Fatalf("冷却中账号应被统计: total=%d cooling=%d", total, cooling)
	}
	if ready.IsZero() || time.Until(ready) > 2*time.Minute+time.Second {
		t.Fatalf("nextReady=%v 应接近 2 分钟后", ready)
	}
	// 冷却已到期:Pick 会复位,不算冷却。
	if err := store.MarkAccountCooldown(accs[0].ID, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, cooling, _, err := resolver.accounts.PoolState("fake"); err != nil || cooling != 0 {
		t.Fatalf("到期冷却不应再统计, cooling=%d err=%v", cooling, err)
	}
}

// 「没有可用账号」的提示必须区分三态:没配账号 / 账号冷却中 / 账号全部过期。
// 生产实证(2026-11-17,百度 9013):风控把唯一账号打进冷却后,后续文件被
// 提示「请先在账号管理添加账号」——账号明明存在。
func TestAuthHintDistinguishesCooling(t *testing.T) {
	hintOf := func(t *testing.T, resolver *Resolver) string {
		t.Helper()
		err := resolver.mapErr(WithAuthed(context.Background(), true), "fake", nil,
			driver.NewErr(driver.KindAuthExpired, "上游要求登录态", nil))
		var de *driver.Error
		if !errors.As(err, &de) {
			t.Fatalf("want driver.Error, got %v", err)
		}
		return de.UserHint
	}

	// 没配账号。
	r1, _ := newTestResolver(t, &twoFileDriver{}, config.DriverCommon{Enabled: true, LimitQPS: 1000, DownloadConc: 3})
	if h := hintOf(t, r1); !strings.Contains(h, "添加账号") {
		t.Fatalf("无账号时应提示添加账号, got %q", h)
	}

	// 账号冷却中:不得说「添加账号」,要给冷却与等待时间。
	r2, store2 := newTestResolver(t, &twoFileDriver{}, config.DriverCommon{Enabled: true, LimitQPS: 1000, DownloadConc: 3})
	seedCookieAccount(t, store2)
	accs, _ := store2.ListAccounts("fake")
	if err := store2.MarkAccountCooldown(accs[0].ID, time.Now().Add(90*time.Second)); err != nil {
		t.Fatal(err)
	}
	h := hintOf(t, r2)
	if !strings.Contains(h, "冷却") || strings.Contains(h, "添加账号") {
		t.Fatalf("冷却中应提示冷却而不是添加账号, got %q", h)
	}
	if !strings.Contains(h, "秒后可再试") {
		t.Fatalf("冷却提示应带上等待时间, got %q", h)
	}

	// 账号全部过期:提示更新,而不是「添加」。
	r3, store3 := newTestResolver(t, &twoFileDriver{}, config.DriverCommon{Enabled: true, LimitQPS: 1000, DownloadConc: 3})
	seedCookieAccount(t, store3)
	accs3, _ := store3.ListAccounts("fake")
	if err := store3.MarkAccountStatus(accs3[0].ID, "expired"); err != nil {
		t.Fatal(err)
	}
	if h := hintOf(t, r3); !strings.Contains(h, "过期") || strings.Contains(h, "添加账号") {
		t.Fatalf("过期账号应提示更新, got %q", h)
	}
}

// 账号冷却期间的整批解析:列表仍成功(匿名可列),每个文件都带上冷却原因,
// 不得出现 download_url/link_error 双空。
func TestResolveShareCoolingAccountExplainsEveryFile(t *testing.T) {
	d := &twoFileDriver{fn: func(context.Context, string) (driver.DirectLink, error) {
		return driver.DirectLink{}, driver.NewErr(driver.KindAuthExpired, "百度提链需要登录态", nil)
	}}
	resolver, store := newTestResolver(t, d, config.DriverCommon{Enabled: true, LimitQPS: 1000, DownloadConc: 3})
	seedCookieAccount(t, store)
	accs, _ := store.ListAccounts("fake")
	if err := store.MarkAccountCooldown(accs[0].ID, time.Now().Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}

	res, err := resolver.ResolveShare(WithAuthed(context.Background(), true), testShareURL, "", "")
	if err != nil {
		t.Fatalf("账号冷却不应让列表失败: %v", err)
	}
	if !strings.Contains(res.Hint, "冷却") {
		t.Fatalf("hint 应说明账号在冷却, got %q", res.Hint)
	}
	for i, f := range res.Files {
		if f.DownloadURL != "" {
			t.Fatalf("冷却期不应有直链: %+v", f)
		}
		if !strings.Contains(f.LinkError, "冷却") {
			t.Fatalf("第 %d 个文件应说明冷却原因, got %q", i, f.LinkError)
		}
	}
}

// 并发 worker 会在 stop 生效前各自命中同一个鉴权失败:同一句提示只能出现一次。
func TestAutoLinkParallelDedupesHints(t *testing.T) {
	d := &twoFileDriver{fn: func(context.Context, string) (driver.DirectLink, error) {
		return driver.DirectLink{}, driver.NewErr(driver.KindAuthExpired, "凭据已失效,请更新", nil)
	}}
	resolver, store := newTestResolver(t, d, config.DriverCommon{Enabled: true, LimitQPS: 1000, DownloadConc: 3})
	seedCookieAccount(t, store)

	nodes := []driver.FileNode{{FID: "f1", Name: "a.bin"}, {FID: "f2", Name: "b.bin"}}
	items := []FileItem{{FID: "f1", Name: "a.bin"}, {FID: "f2", Name: "b.bin"}}
	_, authBlocked, _, hint := resolver.autoLinkParallel(WithAuthed(context.Background(), true),
		testShareURL, "", nodes, items, []int{0, 1}, 2, "", "fake")
	if !authBlocked {
		t.Fatal("鉴权失败应判定为停链")
	}
	if got := strings.Count(hint, "凭据已失效"); got != 1 {
		t.Fatalf("同一提示只应出现一次, got %d 次: %q", got, hint)
	}
}

// 账号池查询失败不得伪装成「没配账号」:那会把用户引去账号页做无效操作,
// 真因(DB 忙/锁/磁盘)也看不到。
func TestPoolStateSurfacesStoreError(t *testing.T) {
	resolver, store := newTestResolver(t, &twoFileDriver{},
		config.DriverCommon{Enabled: true, LimitQPS: 1000, DownloadConc: 3})
	seedCookieAccount(t, store)
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	if _, _, _, err := resolver.accounts.PoolState("fake"); err == nil {
		t.Fatal("ListAccounts 失败必须向上返回错误,不能拿全零顶替")
	}
	err := resolver.mapErr(WithAuthed(context.Background(), true), "fake", nil,
		driver.NewErr(driver.KindAuthExpired, "上游要求登录态", nil))
	var de *driver.Error
	if !errors.As(err, &de) {
		t.Fatalf("want driver.Error, got %v", err)
	}
	if strings.Contains(de.UserHint, "添加账号") {
		t.Fatalf("DB 故障不得提示「添加账号」: %q", de.UserHint)
	}
	if !strings.Contains(de.UserHint, "暂不可用") {
		t.Fatalf("应给中性提示: %q", de.UserHint)
	}
}
