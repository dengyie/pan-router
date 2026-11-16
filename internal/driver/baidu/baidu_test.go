package baidu

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dengyie/panrouter/internal/driver"
	"github.com/dengyie/panrouter/internal/pkg/httpx"
)

func newTestDriver(t *testing.T, h http.Handler) *Driver {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	cl, err := httpx.New(httpx.Options{Timeout: 5 * time.Second, AllowPrivate: true, RedirectAllow: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatalf("httpx.New: %v", err)
	}
	return New(cl, srv.URL).WithPCSBase(srv.URL)
}

func cred() *driver.Credential { return &driver.Credential{Cookie: "BDUSS=abc; STOKEN=def"} }

// waitSweep 等后台清扫结束:清扫不再是同步调用,断言前必须等它跑完,
// 否则会与 handler 闭包跨 goroutine 读写(数据竞争)。
func (d *Driver) waitSweep() { d.sweepWG.Wait() }

// ledgerHas 直接查台账(不经 reuseCopy 的闲置超时判定)。
func (d *Driver) ledgerHas(cookie, shareID, fsid string) bool {
	d.copyMu.Lock()
	defer d.copyMu.Unlock()
	_, ok := d.copies[copyKey(cookie, shareID, fsid)]
	return ok
}

// ledgerAt 读台账里的最近使用时间(测试用)。
func (d *Driver) ledgerAt(cookie, shareID, fsid string) time.Time {
	d.copyMu.Lock()
	defer d.copyMu.Unlock()
	return d.copies[copyKey(cookie, shareID, fsid)].at
}

// ledgerFsid 读台账里的副本 fs_id(测试用)。
func (d *Driver) ledgerFsid(cookie, shareID, fsid string) string {
	d.copyMu.Lock()
	defer d.copyMu.Unlock()
	return d.copies[copyKey(cookie, shareID, fsid)].fsid
}

// 新旧 surl 格式都必须识别:新格式含 `_`/`-`(base64url),旧实现会误报 STOKEN 缺失。
func TestParseShareFormats(t *testing.T) {
	cases := []struct {
		name, in, pwd, wantSurl, wantPwd string
	}{
		{"old base62", "https://pan.baidu.com/s/1AbCdEfGhIjKlMnOpQrStUv", "", "AbCdEfGhIjKlMnOpQrStUv", ""},
		{"new base64url", "https://pan.baidu.com/s/1sjaPJJvG00g3B_aaU-zw6w", "", "sjaPJJvG00g3B_aaU-zw6w", ""},
		{"pwd in query", "https://pan.baidu.com/s/1AbCdEfGhIjKlMnOpQrStUv?pwd=ab12", "", "AbCdEfGhIjKlMnOpQrStUv", "ab12"},
		{"surl form", "https://pan.baidu.com/share/init?surl=AbCdEfGhIjKlMnOpQrStUv", "", "AbCdEfGhIjKlMnOpQrStUv", ""},
		{"explicit pwd", "https://pan.baidu.com/s/1AbCdEfGhIjKlMnOpQrStUv", "zz99", "AbCdEfGhIjKlMnOpQrStUv", "zz99"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			surl, pwd, err := parseShare(driver.ShareLink{URL: c.in, Pwd: c.pwd})
			if err != nil {
				t.Fatalf("parseShare: %v", err)
			}
			if surl != c.wantSurl || pwd != c.wantPwd {
				t.Fatalf("got surl=%q pwd=%q, want %q %q", surl, pwd, c.wantSurl, c.wantPwd)
			}
		})
	}
	if _, _, err := parseShare(driver.ShareLink{URL: "https://example.com/x"}); err == nil {
		t.Fatal("non-baidu URL must fail")
	}
}

func TestClassifyErrno(t *testing.T) {
	cases := []struct {
		errno int
		msg   string
		want  driver.Kind
	}{
		{-6, "", driver.KindAuthExpired},
		{-20, "", driver.KindAuthExpired},
		{2, "提取码错误", driver.KindNotFound},
		{105, "", driver.KindUpstream},
		{110, "", driver.KindShareGone},
		{140, "", driver.KindShareGone},
		{113, "", driver.KindShareGone},
		{9019, "", driver.KindRiskControl},
		// 转存黑名单:高频「转存→删除」触发,不可重试,必须明确报风控。
		{9013, "hit black uid share transfer", driver.KindRiskControl},
		{31066, "", driver.KindRiskControl},
		// filemanager 安全验证拦截(响应带 authwidget/safetpl):不可重试,归风控。
		{132, "", driver.KindRiskControl},
		{31061, "", driver.KindConflict},
		{111, "", driver.KindUpstream},
		{200025, "", driver.KindNotFound},
		{200025, "提取码输入错误,请重试", driver.KindNotFound},
		{42, "请稍后重试", driver.KindRiskControl},
		{42, "分享已取消", driver.KindShareGone},
		{42, "unexpected", driver.KindUpstream},
	}
	for _, c := range cases {
		de := classifyErrno(c.errno, c.msg)
		if de == nil {
			t.Fatalf("errno=%d: expected error", c.errno)
		}
		if de.Kind != c.want {
			t.Fatalf("errno=%d msg=%q: kind=%s want %s", c.errno, c.msg, de.Kind, c.want)
		}
	}
	if classifyErrno(0, "") != nil {
		t.Fatal("errno 0 must be nil")
	}
}

// 分享解析:根目录 root=1;子目录 root=0 且必须带 BDCLND(=sekey);节点 Ext 带转存上下文。
func TestResolveShareWalksAndCarriesContext(t *testing.T) {
	var sawRoot, sawSub, sawBDCLND bool
	d := newTestDriver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/share/verify":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "randsk": "%2Bsekey%3D"})
		case "/rest/2.0/xpan/share":
			q := r.URL.Query()
			// randsk 是 URL 编码形态,进查询参数前必须归一化成解码形态:
			// 否则 net/url 再编码一次 → 双重编码 → 百度判「提取码错误」(200025)。
			if q.Get("sekey") != "+sekey=" {
				t.Errorf("sekey must be normalized (decoded) once: %q", q.Get("sekey"))
			}
			if q.Get("root") == "1" {
				sawRoot = true
				_ = json.NewEncoder(w).Encode(map[string]any{
					"errno": 0, "share_id": 12345, "uk": 67890,
					"list": []map[string]any{
						{"fs_id": 111, "isdir": "0", "path": "/a.bin", "server_filename": "a.bin", "size": 5},
						{"fs_id": 222, "isdir": "1", "path": "/sub", "server_filename": "sub"},
					},
				})
				return
			}
			if q.Get("dir") == "/sub" {
				sawSub = true
				if strings.Contains(r.Header.Get("Cookie"), "BDCLND=+sekey=") {
					sawBDCLND = true
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"errno": 0,
					"list": []map[string]any{
						{"fs_id": 333, "isdir": "0", "path": "/sub/b.txt", "server_filename": "b.txt", "size": 7},
					},
				})
				return
			}
			t.Errorf("unexpected list dir=%q root=%q", q.Get("dir"), q.Get("root"))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))

	nodes, err := d.ResolveShare(context.Background(), driver.ShareLink{
		URL: "https://pan.baidu.com/s/1sjaPJJvG00g3B_aaU-zw6w", Pwd: "ab12",
	}, cred())
	if err != nil {
		t.Fatalf("ResolveShare: %v", err)
	}
	if !sawRoot || !sawSub || !sawBDCLND {
		t.Fatalf("root=%v sub=%v bdclnd=%v", sawRoot, sawSub, sawBDCLND)
	}
	if len(nodes) != 2 {
		t.Fatalf("want 2 files, got %d: %+v", len(nodes), nodes)
	}
	if nodes[0].Name != "a.bin" || nodes[1].Name != "sub/b.txt" {
		t.Fatalf("names: %q %q", nodes[0].Name, nodes[1].Name)
	}
	for _, n := range nodes {
		if n.Ext["share_id"] != "12345" || n.Ext["uk"] != "67890" || n.Ext["sekey"] != "+sekey=" {
			t.Fatalf("missing context: %+v", n.Ext)
		}
	}
}

// 生产实证(2026-11-13):xpan/share 的 size 有时是字符串("123"),直接解成
// int64 会让整次解析误报 interface_changed。number 与 string 都必须能读。
func TestResolveShareToleratesStringSize(t *testing.T) {
	d := newTestDriver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"errno": 0,
			"list": []map[string]any{
				{"fs_id": 111, "isdir": "0", "path": "/a.bin", "server_filename": "a.bin", "size": "12345"},
				{"fs_id": "222", "isdir": 0, "path": "/b.bin", "server_filename": "b.bin", "size": 678},
			},
		})
	}))
	nodes, err := d.ResolveShare(context.Background(), driver.ShareLink{
		URL: "https://pan.baidu.com/s/1AbCdEfGhIjKlMnOpQrStUv",
	}, nil)
	if err != nil {
		t.Fatalf("ResolveShare: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("want 2 files, got %d: %+v", len(nodes), nodes)
	}
	if nodes[0].Size != 12345 || nodes[1].Size != 678 {
		t.Fatalf("sizes: %d %d", nodes[0].Size, nodes[1].Size)
	}
	if nodes[0].FID != "111" || nodes[1].FID != "222" {
		t.Fatalf("fids: %q %q", nodes[0].FID, nodes[1].FID)
	}
}

// 加密分享未给提取码:应提示需要提取码,而不是笼统的上游错误。
func TestResolveShareNeedsPwd(t *testing.T) {
	d := newTestDriver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"errno": 2, "errmsg": "need pwd"})
	}))
	_, err := d.ResolveShare(context.Background(), driver.ShareLink{URL: "https://pan.baidu.com/s/1AbCdEfGhIjKlMnOpQrStUv"}, nil)
	var de *driver.Error
	if !errors.As(err, &de) || de.Kind != driver.KindNotFound {
		t.Fatalf("want not_found, got %v", err)
	}
}

// 转存链:暂存目录 → 转存 → locatedownload 选 encrypt=0;副本留在台账里复用,
// **不**在提链后立刻删除(那正是把账号送进转存黑名单的循环)。
func TestGetDirectLinkTransferChain(t *testing.T) {
	var transferred, sawSekey, deleted bool
	d := newTestDriver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/gettemplatevariable":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "result": map[string]string{"bdstoken": "tok"}})
		case "/api/create":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
		case "/rest/2.0/xpan/file":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "list": []map[string]any{}})
		case "/share/transfer":
			_ = r.ParseForm()
			transferred = r.Form.Get("fsidlist") == `["111"]` && r.Form.Get("path") == "/panrouter_tmp"
			// Ext 里存的是存量快照的编码形态,转存查询参数必须是**单次编码**的
			// 解码值(即 "+sekey="),双编码会让百度回 200025 提取码错误。
			sawSekey = r.URL.Query().Get("sekey") == "+sekey="
			_ = json.NewEncoder(w).Encode(map[string]any{
				"errno": 0,
				"extra": map[string]any{"list": []map[string]any{
					{"to_fs_id": "999", "to": "/panrouter_tmp/a.bin"},
				}},
			})
		case "/rest/2.0/pcs/file":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"errno": 0,
				"urls": []map[string]any{
					{"url": "https://d2-ant.baidu.com/enc", "encrypt": 1},
					{"url": "https://appall01.baidupcs.com/plain", "encrypt": 0},
				},
			})
		case "/api/filemanager":
			deleted = true
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))

	dl, err := d.GetDirectLink(context.Background(), cred(), driver.FileRef{
		FID: "111",
		Ext: map[string]string{"share_id": "12345", "uk": "67890", "sekey": "%2Bsekey%3D"},
	})
	if err != nil {
		t.Fatalf("GetDirectLink: %v", err)
	}
	if !transferred {
		t.Fatal("transfer body mismatch")
	}
	if !sawSekey {
		t.Fatal("transfer 查询参数里的 sekey 必须是解码形态(单次编码),否则百度回 200025")
	}
	if dl.URL != "https://appall01.baidupcs.com/plain" {
		t.Fatalf("want encrypt=0 https link, got %q", dl.URL)
	}
	if dl.UA != NetdiskUA || !strings.Contains(dl.Cookie, "BDUSS=abc") {
		t.Fatalf("link constraints: ua=%q cookie=%q", dl.UA, dl.Cookie)
	}
	d.waitSweep()
	if deleted {
		t.Fatal("首次提链不得立刻删除副本:高频「转存→删除」会被百度拉黑转存权限(errno=9013)")
	}
	if _, ok := d.reuseCopy(cred().Cookie, "12345", "111"); !ok {
		t.Fatal("转存后的副本必须进台账,供后续提链复用")
	}
}

// 台账命中的副本:第二次提链只重取直链,不得再转存(也不消耗当日转存配额)。
func TestGetDirectLinkReusesCopy(t *testing.T) {
	var transfers int
	var locatedAt string
	d := newTestDriver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/gettemplatevariable":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "result": map[string]string{"bdstoken": "tok"}})
		case "/api/create":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
		case "/rest/2.0/xpan/file":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "list": []map[string]any{}})
		case "/share/transfer":
			transfers++
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "extra": map[string]any{"list": []map[string]any{
				{"to_fs_id": "999", "to": "/panrouter_tmp/a.bin"},
			}}})
		case "/rest/2.0/pcs/file":
			locatedAt = r.URL.Query().Get("path")
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "urls": []map[string]any{
				{"url": "https://appall01.baidupcs.com/plain", "encrypt": 0},
			}})
		case "/api/filemanager":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))

	ref := driver.FileRef{FID: "111", Ext: map[string]string{"share_id": "12345", "uk": "67890", "sekey": "+sekey="}}
	if _, err := d.GetDirectLink(context.Background(), cred(), ref); err != nil {
		t.Fatalf("first GetDirectLink: %v", err)
	}
	d.waitSweep()
	dl, err := d.GetDirectLink(context.Background(), cred(), ref)
	if err != nil {
		t.Fatalf("second GetDirectLink: %v", err)
	}
	if transfers != 1 {
		t.Fatalf("复用副本时不得再次转存, transfers=%d", transfers)
	}
	if locatedAt != "/panrouter_tmp/a.bin" {
		t.Fatalf("复用必须按台账里的路径取链, got path=%q", locatedAt)
	}
	if !strings.Contains(dl.Cookie, "BDCLND=+sekey=") {
		t.Fatalf("复用取链同样要带分享验证 Cookie, got %q", dl.Cookie)
	}
}

// 清扫以远端目录为准:闲置超时的批量删,未过期的、仍在复用的一律留着。
func TestSweepCopiesDeletesExpired(t *testing.T) {
	var deletedList string
	oldMtime := time.Now().Add(-2 * copyTTL).Unix()
	d := newTestDriver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/gettemplatevariable":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "result": map[string]string{"bdstoken": "tok"}})
		case "/api/create":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
		case "/rest/2.0/xpan/file":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "list": []map[string]any{
				{"path": "/panrouter_tmp/old.bin", "server_mtime": oldMtime},
				{"path": "/panrouter_tmp/fresh.bin", "server_mtime": time.Now().Unix()},
			}})
		case "/share/transfer":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "extra": map[string]any{"list": []map[string]any{
				{"to_fs_id": "999", "to": "/panrouter_tmp/new.bin"},
			}}})
		case "/rest/2.0/pcs/file":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "urls": []map[string]any{
				{"url": "https://appall01.baidupcs.com/plain", "encrypt": 0},
			}})
		case "/api/filemanager":
			_ = r.ParseForm()
			deletedList = r.Form.Get("filelist")
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))

	old := time.Now().Add(-2 * copyTTL)
	d.rememberCopy(cred().Cookie, "OLD", "1", copyEntry{fsid: "888", path: "/panrouter_tmp/old.bin", at: old})
	d.rememberCopy(cred().Cookie, "FRESH", "2", copyEntry{fsid: "889", path: "/panrouter_tmp/fresh.bin", at: time.Now()})

	if _, err := d.GetDirectLink(context.Background(), cred(), driver.FileRef{
		FID: "111", Ext: map[string]string{"share_id": "12345", "uk": "67890"},
	}); err != nil {
		t.Fatalf("GetDirectLink: %v", err)
	}
	d.waitSweep()
	if !strings.Contains(deletedList, "/panrouter_tmp/old.bin") {
		t.Fatalf("闲置超时副本必须被清扫, filelist=%q", deletedList)
	}
	if strings.Contains(deletedList, "/panrouter_tmp/fresh.bin") {
		t.Fatalf("未过期副本不得删除, filelist=%q", deletedList)
	}
	if d.ledgerHas(cred().Cookie, "OLD", "1") {
		t.Fatal("已清扫的副本必须从台账移除")
	}
	if !d.ledgerHas(cred().Cookie, "FRESH", "2") {
		t.Fatal("未过期副本必须留在台账")
	}
}

// 重启/换 Cookie 后台账是空的:远端残留副本(台账外)也必须按 mtime 清掉,
// 否则每次发版都会在用户网盘里留下一份永不清理的副本。
func TestSweepCopiesDeletesRemoteOrphans(t *testing.T) {
	var deletedList string
	oldMtime := time.Now().Add(-2 * copyTTL).Unix()
	d := newTestDriver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/gettemplatevariable":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "result": map[string]string{"bdstoken": "tok"}})
		case "/api/create":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
		case "/rest/2.0/xpan/file":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "list": []map[string]any{
				{"path": "/panrouter_tmp/leftover.bin", "server_mtime": oldMtime},
				{"path": "/panrouter_tmp/just-now.bin", "server_mtime": time.Now().Unix()},
			}})
		case "/share/transfer":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "extra": map[string]any{"list": []map[string]any{
				{"to_fs_id": "999", "to": "/panrouter_tmp/new.bin"},
			}}})
		case "/rest/2.0/pcs/file":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "urls": []map[string]any{
				{"url": "https://appall01.baidupcs.com/plain", "encrypt": 0},
			}})
		case "/api/filemanager":
			_ = r.ParseForm()
			deletedList = r.Form.Get("filelist")
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))

	if _, err := d.GetDirectLink(context.Background(), cred(), driver.FileRef{
		FID: "111", Ext: map[string]string{"share_id": "12345", "uk": "67890"},
	}); err != nil {
		t.Fatalf("GetDirectLink: %v", err)
	}
	d.waitSweep()
	if !strings.Contains(deletedList, "/panrouter_tmp/leftover.bin") {
		t.Fatalf("台账外的陈旧副本必须清掉(否则重启后无人清理), filelist=%q", deletedList)
	}
	if strings.Contains(deletedList, "/panrouter_tmp/just-now.bin") {
		t.Fatalf("刚写入的副本可能属于在途转存,不得删除, filelist=%q", deletedList)
	}
}

// 复用中(at 刷新过)的副本:即使远端 mtime 很旧也不得删——复用只重取直链,
// 不会更新文件 mtime,判活只能靠台账的 at。
func TestSweepCopiesKeepsLiveCopy(t *testing.T) {
	var deletedList string
	oldMtime := time.Now().Add(-2 * copyTTL).Unix()
	d := newTestDriver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/gettemplatevariable":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "result": map[string]string{"bdstoken": "tok"}})
		case "/api/create":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
		case "/rest/2.0/xpan/file":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "list": []map[string]any{
				{"path": "/panrouter_tmp/hot.bin", "server_mtime": oldMtime},
			}})
		case "/share/transfer":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "extra": map[string]any{"list": []map[string]any{
				{"to_fs_id": "999", "to": "/panrouter_tmp/new.bin"},
			}}})
		case "/rest/2.0/pcs/file":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "urls": []map[string]any{
				{"url": "https://appall01.baidupcs.com/plain", "encrypt": 0},
			}})
		case "/api/filemanager":
			_ = r.ParseForm()
			deletedList = r.Form.Get("filelist")
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))

	// at 是刚刚(仍在复用),远端 mtime 却是 8 小时前:必须按 at 判活。
	d.rememberCopy(cred().Cookie, "HOT", "1", copyEntry{
		fsid: "777", path: "/panrouter_tmp/hot.bin", at: time.Now(),
	})
	if _, err := d.GetDirectLink(context.Background(), cred(), driver.FileRef{
		FID: "111", Ext: map[string]string{"share_id": "12345", "uk": "67890"},
	}); err != nil {
		t.Fatalf("GetDirectLink: %v", err)
	}
	d.waitSweep()
	if strings.Contains(deletedList, "/panrouter_tmp/hot.bin") {
		t.Fatalf("仍在复用的副本不得删除, filelist=%q", deletedList)
	}
}

// 删除失败不得提前丢台账:丢了就再也没人清那份云端副本了(下次扫到要能重试)。
func TestSweepCopiesKeepsLedgerOnDeleteFailure(t *testing.T) {
	oldMtime := time.Now().Add(-2 * copyTTL).Unix()
	d := newTestDriver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/gettemplatevariable":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "result": map[string]string{"bdstoken": "tok"}})
		case "/api/create":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
		case "/rest/2.0/xpan/file":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "list": []map[string]any{
				{"path": "/panrouter_tmp/old.bin", "server_mtime": oldMtime},
			}})
		case "/share/transfer":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "extra": map[string]any{"list": []map[string]any{
				{"to_fs_id": "999", "to": "/panrouter_tmp/new.bin"},
			}}})
		case "/rest/2.0/pcs/file":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "urls": []map[string]any{
				{"url": "https://appall01.baidupcs.com/plain", "encrypt": 0},
			}})
		case "/api/filemanager":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 31064, "errmsg": "delete failed"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))

	d.rememberCopy(cred().Cookie, "OLD", "1", copyEntry{
		fsid: "888", path: "/panrouter_tmp/old.bin", at: time.Now().Add(-2 * copyTTL),
	})
	if _, err := d.GetDirectLink(context.Background(), cred(), driver.FileRef{
		FID: "111", Ext: map[string]string{"share_id": "12345", "uk": "67890"},
	}); err != nil {
		t.Fatalf("GetDirectLink: %v", err)
	}
	d.waitSweep()
	if !d.ledgerHas(cred().Cookie, "OLD", "1") {
		t.Fatal("删除失败时不得丢台账,否则云端副本永远无人清理")
	}
}

// 删除被风控/安全验证拦下(errno=132)时,按普通周期重试只是反复喂风控:下一次
// 清扫必须显著推后,而不是 10 分钟后又拿同一批路径去戳一次。
func TestSweepRiskControlBacksOff(t *testing.T) {
	oldMtime := time.Now().Add(-2 * copyTTL).Unix()
	d := newTestDriver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/gettemplatevariable":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "result": map[string]string{"bdstoken": "tok"}})
		case "/api/create":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
		case "/rest/2.0/xpan/file":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "list": []map[string]any{
				{"path": "/panrouter_tmp/old.bin", "server_mtime": oldMtime},
			}})
		case "/share/transfer":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "extra": map[string]any{"list": []map[string]any{
				{"to_fs_id": "999", "to": "/panrouter_tmp/new.bin"},
			}}})
		case "/rest/2.0/pcs/file":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "urls": []map[string]any{
				{"url": "https://appall01.baidupcs.com/plain", "encrypt": 0},
			}})
		case "/api/filemanager":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 132, "authwidget": map[string]any{"safetpl": "filemanager"}})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))

	d.rememberCopy(cred().Cookie, "OLD", "1", copyEntry{
		fsid: "888", path: "/panrouter_tmp/old.bin", at: time.Now().Add(-2 * copyTTL),
	})
	if _, err := d.GetDirectLink(context.Background(), cred(), driver.FileRef{
		FID: "111", Ext: map[string]string{"share_id": "12345", "uk": "67890"},
	}); err != nil {
		t.Fatalf("GetDirectLink: %v", err)
	}
	d.waitSweep()
	d.copyMu.Lock()
	next := d.sweepAt[fingerprint(cred().Cookie)]
	d.copyMu.Unlock()
	if time.Until(next) < 30*time.Minute {
		t.Fatalf("风控拦截后应显著推后下次清扫, next=%v", time.Until(next))
	}
	if !d.ledgerHas(cred().Cookie, "OLD", "1") {
		t.Fatal("风控拦截不得丢台账")
	}
}

// 同一账号的清扫按 copySweepInterval 节流:连续提链不该每次都发删除请求。
func TestSweepCopiesThrottled(t *testing.T) {
	var deletes int
	stale := time.Now().Add(-2 * copyTTL).Unix()
	items := make([]map[string]any, 0, 3)
	for i := 0; i < 3; i++ {
		items = append(items, map[string]any{
			"path": "/panrouter_tmp/old" + itoa(i), "server_mtime": stale,
		})
	}
	d := newTestDriver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/gettemplatevariable":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "result": map[string]string{"bdstoken": "tok"}})
		case "/api/create":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
		case "/rest/2.0/xpan/file":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "list": items})
		case "/share/transfer":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "extra": map[string]any{"list": []map[string]any{
				{"to_fs_id": "999", "to": "/panrouter_tmp/a.bin"},
			}}})
		case "/rest/2.0/pcs/file":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "urls": []map[string]any{
				{"url": "https://appall01.baidupcs.com/plain", "encrypt": 0},
			}})
		case "/api/filemanager":
			deletes++
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))

	for i := 0; i < 3; i++ {
		d.rememberCopy(cred().Cookie, "OLD"+itoa(i), "1", copyEntry{
			fsid: "88" + itoa(i), path: "/panrouter_tmp/old" + itoa(i), at: time.Now().Add(-2 * copyTTL),
		})
		if _, err := d.GetDirectLink(context.Background(), cred(), driver.FileRef{
			FID: itoa(100 + i), Ext: map[string]string{"share_id": "12345", "uk": "67890"},
		}); err != nil {
			t.Fatalf("GetDirectLink %d: %v", i, err)
		}
		d.waitSweep()
	}
	if deletes != 1 {
		t.Fatalf("清扫必须节流:3 次提链只应删 1 次, got %d", deletes)
	}
}

// 复用命中要刷新闲置计时:否则天天在用的副本也会在 4 小时后被判过期并重转,
// 等于每个直链周期又转存一次(正是要压掉的刷量)。
func TestReuseCopyRefreshesIdleTimer(t *testing.T) {
	var transfers int
	d := newTestDriver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/gettemplatevariable":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "result": map[string]string{"bdstoken": "tok"}})
		case "/api/create":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
		case "/share/transfer":
			transfers++
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
		case "/rest/2.0/pcs/file":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "urls": []map[string]any{
				{"url": "https://appall01.baidupcs.com/plain", "encrypt": 0},
			}})
		case "/rest/2.0/xpan/file":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "list": []map[string]any{}})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))

	d.rememberCopy(cred().Cookie, "12345", "111", copyEntry{
		fsid: "999", path: "/panrouter_tmp/a.bin", at: time.Now().Add(-3 * time.Hour),
	})
	if _, err := d.GetDirectLink(context.Background(), cred(), driver.FileRef{
		FID: "111", Ext: map[string]string{"share_id": "12345", "uk": "67890"},
	}); err != nil {
		t.Fatalf("GetDirectLink: %v", err)
	}
	if transfers != 0 {
		t.Fatalf("副本未闲置超时,不得重转, transfers=%d", transfers)
	}
	if at := d.ledgerAt(cred().Cookie, "12345", "111"); time.Since(at) > time.Minute {
		t.Fatalf("复用命中必须刷新 at(闲置计时), at=%v", at)
	}
}

// 复用失败若是网络/风控等瞬时问题:副本多半还在,不得丢台账重转(那是白烧配额
// 加刷量记录),而应如实报错、保留台账。
func TestReuseTransientFailureKeepsCopy(t *testing.T) {
	var transfers int
	d := newTestDriver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/gettemplatevariable":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "result": map[string]string{"bdstoken": "tok"}})
		case "/api/create":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
		case "/share/transfer":
			transfers++
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
		case "/rest/2.0/pcs/file":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": -1, "errmsg": "psign invalid"})
		case "/api/filemetas":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": -1, "errmsg": "service busy"})
		case "/rest/2.0/xpan/file":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "list": []map[string]any{}})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))

	d.rememberCopy(cred().Cookie, "12345", "111", copyEntry{
		fsid: "999", path: "/panrouter_tmp/a.bin", at: time.Now(),
	})
	_, err := d.GetDirectLink(context.Background(), cred(), driver.FileRef{
		FID: "111", Ext: map[string]string{"share_id": "12345", "uk": "67890"},
	})
	if err == nil {
		t.Fatal("两条取链路径都失败时必须如实报错")
	}
	d.waitSweep()
	if transfers != 0 {
		t.Fatalf("瞬时失败不得重新转存(刷量/配额风险), transfers=%d", transfers)
	}
	if !d.ledgerHas(cred().Cookie, "12345", "111") {
		t.Fatal("瞬时失败不得丢台账,否则下次还得重转")
	}
}

// 副本确实不在了(百度回「文件不存在」):必须丢台账重转,否则该文件永远提不出链。
func TestReuseGoneCopyRetransfers(t *testing.T) {
	var transfers, locates int
	d := newTestDriver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/gettemplatevariable":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "result": map[string]string{"bdstoken": "tok"}})
		case "/api/create":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
		case "/api/filemetas":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": -9, "errmsg": "file not found"})
		case "/rest/2.0/pcs/file":
			locates++
			if locates == 1 {
				_ = json.NewEncoder(w).Encode(map[string]any{"errno": -9, "errmsg": "file not found"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "urls": []map[string]any{
				{"url": "https://appall01.baidupcs.com/plain", "encrypt": 0},
			}})
		case "/share/transfer":
			transfers++
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "extra": map[string]any{"list": []map[string]any{
				{"to_fs_id": "999", "to": "/panrouter_tmp/a.bin"},
			}}})
		case "/rest/2.0/xpan/file":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "list": []map[string]any{}})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))

	d.rememberCopy(cred().Cookie, "12345", "111", copyEntry{
		fsid: "888", path: "/panrouter_tmp/gone.bin", at: time.Now(),
	})
	if _, err := d.GetDirectLink(context.Background(), cred(), driver.FileRef{
		FID: "111", Ext: map[string]string{"share_id": "12345", "uk": "67890"},
	}); err != nil {
		t.Fatalf("副本已不存在时应重转成功: %v", err)
	}
	d.waitSweep()
	if transfers != 1 {
		t.Fatalf("副本确认不存在必须重转一次, transfers=%d", transfers)
	}
	if got := d.ledgerFsid(cred().Cookie, "12345", "111"); got != "999" {
		t.Fatalf("重转后台账必须换成新副本 fs_id, got %q", got)
	}
}

// locatedownload 失败(常量被轮换)时必须退回 filemetas。
func TestGetDirectLinkFallsBackToFilemetas(t *testing.T) {
	var metas bool
	d := newTestDriver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/gettemplatevariable":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "result": map[string]string{"bdstoken": "tok"}})
		case "/api/create":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
		case "/rest/2.0/xpan/file":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "list": []map[string]any{}})
		case "/share/transfer":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "extra": map[string]any{"list": []map[string]any{
				{"to_fs_id": "999", "to": "/panrouter_tmp/a.bin"},
			}}})
		case "/rest/2.0/pcs/file":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": -1, "errmsg": "psign invalid"})
		case "/api/filemetas":
			metas = true
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "info": []map[string]any{
				{"dlink": "https://d.pcs.baidu.com/rest/2.0/pcs/file?fid=999&sign=x"},
			}})
		case "/api/filemanager":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	dl, err := d.GetDirectLink(context.Background(), cred(), driver.FileRef{
		FID: "111", Ext: map[string]string{"share_id": "1", "uk": "2"},
	})
	if err != nil {
		t.Fatalf("GetDirectLink: %v", err)
	}
	if !metas || !strings.Contains(dl.URL, "fid=999") {
		t.Fatalf("fallback not used: metas=%v url=%q", metas, dl.URL)
	}
}

// 日转存硬闸:达上限后返回风控错误,不允许继续硬闯。
func TestTransferQuotaGate(t *testing.T) {
	d := New(nil, "")
	for i := 0; i < DailyTransferLimit; i++ {
		if err := d.takeTransferQuota("BDUSS=x"); err != nil {
			t.Fatalf("take %d: %v", i, err)
		}
	}
	err := d.takeTransferQuota("BDUSS=x")
	var de *driver.Error
	if !errors.As(err, &de) || de.Kind != driver.KindRiskControl {
		t.Fatalf("want risk_control, got %v", err)
	}
	// 另一账号互不影响。
	if err := d.takeTransferQuota("BDUSS=y"); err != nil {
		t.Fatalf("other account: %v", err)
	}
}

func TestCheckCredential(t *testing.T) {
	valid := newTestDriver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "result": map[string]string{"username": "nick", "bdstoken": "tok"}})
	}))
	st, err := valid.CheckCredential(context.Background(), driver.Credential{Cookie: "BDUSS=abc"})
	if err != nil || !st.Valid || st.Nickname != "nick" {
		t.Fatalf("valid: %+v %v", st, err)
	}

	expired := newTestDriver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"errno": -6, "errmsg": "not login"})
	}))
	st, err = expired.CheckCredential(context.Background(), driver.Credential{Cookie: "BDUSS=old"})
	if err != nil || st.Valid {
		t.Fatalf("expired: %+v %v", st, err)
	}
}

func TestCookieHeader(t *testing.T) {
	if got := cookieHeader("BDUSS=a", "%2Bsk%3D"); got != "BDUSS=a; BDCLND=%2Bsk%3D" {
		t.Fatalf("append: %q", got)
	}
	if got := cookieHeader("BDUSS=a; BDCLND=x", "y"); got != "BDUSS=a; BDCLND=x" {
		t.Fatalf("no dup: %q", got)
	}
	if got := cookieHeader("", "sk"); got != "BDCLND=sk" {
		t.Fatalf("empty base: %q", got)
	}
	_ = url.Values{}
}

// sekey 归一化:百度 randsk 是 URL 编码形态,进查询参数前必须解码一次;
// 已解码值必须原样返回(幂等),否则存量快照会被二次解码。
func TestNormalizeSekey(t *testing.T) {
	cases := []struct{ in, want string }{
		{"%2Bsekey%3D", "+sekey="}, // verify 返回的编码形态 → 解码
		{"+sekey=", "+sekey="},     // 已解码 → 原样(幂等)
		{"abcDEF123", "abcDEF123"}, // 无 "%" 的普通 randsk → 原样
		{"a%2Fb%2Bc%3D", "a/b+c="}, // 多个转义
		{"a+b%2Bc", "a+b+c"},       // 字面 "+" 必须保留(QueryUnescape 会解成空格)
		{"%zz", "%zz"},             // 非法转义 → 原样(不丢值)
		{"", ""},                   // 空值
		{"50%off", "50%off"},       // 含 "%" 但非合法转义序列 → 原样
	}
	for _, c := range cases {
		if got := normalizeSekey(c.in); got != c.want {
			t.Fatalf("normalizeSekey(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if normalizeSekey(normalizeSekey("%2Bsekey%3D")) != "+sekey=" {
		t.Fatal("normalizeSekey must be idempotent")
	}
}

// 转存失败时百度只给 show_msg(生产实证 200025 的 errmsg 为空):
// 必须把 show_msg 回填进错误文案,用户才知道是提取码问题。
func TestTransferSurfacesShowMsg(t *testing.T) {
	d := newTestDriver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/gettemplatevariable":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "result": map[string]string{"bdstoken": "tok"}})
		case "/api/create":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
		case "/share/transfer":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"errno": 200025, "errmsg": "", "show_msg": "提取码输入错误,请重试",
			})
		case "/rest/2.0/xpan/file":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "list": []map[string]any{}})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	_, err := d.GetDirectLink(context.Background(), cred(), driver.FileRef{
		FID: "111",
		Ext: map[string]string{"share_id": "12345", "uk": "67890", "sekey": "+sekey="},
	})
	d.waitSweep()
	var de *driver.Error
	if !errors.As(err, &de) {
		t.Fatalf("want driver.Error, got %v", err)
	}
	if de.Kind != driver.KindNotFound {
		t.Fatalf("kind=%s want not_found", de.Kind)
	}
	if !strings.Contains(de.UserHint, "提取码") {
		t.Fatalf("show_msg 未回填到错误文案: %q", de.UserHint)
	}
}

// 非 JSON 负载要按形态分流:HTML 是风控/验证页(冷却或换号可恢复),
// 不能一律报「接口改版」把人引到不存在的接口变更上去。
func TestClassifyBadBody(t *testing.T) {
	cases := []struct {
		name string
		body string
		want driver.Kind
	}{
		{"html verify page", "<!DOCTYPE html><html><body>安全验证</body></html>", driver.KindRiskControl},
		{"html leading space", "\n  <html><body>verify</body></html>", driver.KindRiskControl},
		{"garbage json", "errno=0&errmsg=ok", driver.KindInterfaceChanged},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			de := classifyBadBody(&httpx.Result{StatusCode: 200, Body: []byte(c.body)}, errors.New("decode"))
			var e *driver.Error
			if !errors.As(de, &e) || e.Kind != c.want {
				t.Fatalf("kind=%v want %s (%v)", de, c.want, de)
			}
		})
	}
}

// 响应片段里若混进凭据字段,必须被抹掉再进错误文案/日志。
func TestSnippetRedactsCredentials(t *testing.T) {
	got := snippet(`{"x":"BDUSS=secretvalue;STOKEN=tok123"} 以及 BDCLND=abc`)
	if strings.Contains(got, "secretvalue") || strings.Contains(got, "tok123") || strings.Contains(got, "abc") {
		t.Fatalf("凭据未被抹掉: %q", got)
	}
	if !strings.Contains(got, "***") {
		t.Fatalf("抹除后应保留 *** 标记: %q", got)
	}
	// 超长片段按 rune 截断,不得切碎多字节字符。
	long := strings.Repeat("百度", 200)
	cut := snippet(long)
	if len([]rune(cut)) != 120 {
		t.Fatalf("snippet 应按 rune 截到 120, got %d", len([]rune(cut)))
	}
}

// 空响应不能被当成「errno=0 成功」:旧实现会让调用方把没建成的目录当已建好。
func TestEmptyBodyIsUpstreamError(t *testing.T) {
	d := newTestDriver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/gettemplatevariable":
			w.WriteHeader(http.StatusBadGateway)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	_, err := d.getBdstoken(context.Background(), cred(), false)
	var de *driver.Error
	if !errors.As(err, &de) || de.Kind != driver.KindUpstream {
		t.Fatalf("空响应必须报 upstream, got %v", err)
	}
	if !strings.Contains(de.UserHint, "空响应") {
		t.Fatalf("提示应说明是空响应: %q", de.UserHint)
	}
}

// 转存响应里的路径是上游输入:一旦越出暂存目录,绝不能入账——台账路径日后会
// 作为批量删除的目标,删的是用户自己的文件且不可逆。
func TestTransferPathOutsideTmpDirRejected(t *testing.T) {
	var deleted bool
	d := newTestDriver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/gettemplatevariable":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "result": map[string]string{"bdstoken": "tok"}})
		case "/api/create":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
		case "/rest/2.0/xpan/file":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "list": []map[string]any{}})
		case "/share/transfer":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "extra": map[string]any{"list": []map[string]any{
				{"to_fs_id": "999", "to": "/我的资源/important.mkv"},
			}}})
		case "/api/filemanager":
			deleted = true
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))

	_, err := d.GetDirectLink(context.Background(), cred(), driver.FileRef{
		FID: "111", Ext: map[string]string{"share_id": "12345", "uk": "67890"},
	})
	var de *driver.Error
	if !errors.As(err, &de) || de.Kind != driver.KindInterfaceChanged {
		t.Fatalf("越界转存路径必须拒绝并报 interface_changed, got %v", err)
	}
	if d.ledgerHas(cred().Cookie, "12345", "111") {
		t.Fatal("越界路径不得入账:台账会被清扫当删除目标")
	}
	d.waitSweep()
	if deleted {
		t.Fatal("越界路径不得触发删除")
	}
}

// 历史台账里若已存在越界路径(入账校验之前写入的),清扫必须既不删也不留。
func TestSweepDropsLedgerPathOutsideTmpDir(t *testing.T) {
	var deletedList string
	d := newTestDriver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/gettemplatevariable":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "result": map[string]string{"bdstoken": "tok"}})
		case "/api/create":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
		case "/rest/2.0/xpan/file":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "list": []map[string]any{}})
		case "/share/transfer":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "extra": map[string]any{"list": []map[string]any{
				{"to_fs_id": "999", "to": "/panrouter_tmp/new.bin"},
			}}})
		case "/rest/2.0/pcs/file":
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "urls": []map[string]any{
				{"url": "https://appall01.baidupcs.com/plain", "encrypt": 0},
			}})
		case "/api/filemanager":
			_ = r.ParseForm()
			deletedList = r.Form.Get("filelist")
			_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))

	old := time.Now().Add(-2 * copyTTL)
	d.rememberCopy(cred().Cookie, "BAD", "9", copyEntry{
		fsid: "777", path: "/我的资源/important.mkv", at: old,
	})

	if _, err := d.GetDirectLink(context.Background(), cred(), driver.FileRef{
		FID: "111", Ext: map[string]string{"share_id": "12345", "uk": "67890"},
	}); err != nil {
		t.Fatalf("GetDirectLink: %v", err)
	}
	d.waitSweep()
	if strings.Contains(deletedList, "我的资源") {
		t.Fatalf("越界台账路径绝不能进删除请求, filelist=%q", deletedList)
	}
	if d.ledgerHas(cred().Cookie, "BAD", "9") {
		t.Fatal("越界台账项应被丢弃(永远不该由我们删除,留着只会每轮重试)")
	}
}

// 列表被截断时不得按「不在列表里」判远端已删。
func TestSplitGoneKeepsLedgerWhenListingIncomplete(t *testing.T) {
	idle := []sweepItem{
		{key: "a", path: "/panrouter_tmp/a.bin"},
		{key: "b", path: "/panrouter_tmp/b.bin"},
	}
	present := map[string]struct{}{"/panrouter_tmp/a.bin": {}}

	keep, gone := splitGone(append([]sweepItem(nil), idle...), present, true)
	if len(keep) != 1 || len(gone) != 1 || keep[0].key != "a" || gone[0].key != "b" {
		t.Fatalf("完整列表:keep=%+v gone=%+v", keep, gone)
	}

	keep, gone = splitGone(append([]sweepItem(nil), idle...), present, false)
	if len(keep) != 2 || len(gone) != 0 {
		t.Fatalf("截断列表不得丢台账:keep=%+v gone=%+v", keep, gone)
	}
}

// 目录超过单页时必须翻页:单页当全量会把最旧的台账项误判成「远端已删」。
func TestListDirPaginates(t *testing.T) {
	var starts []string
	d := newTestDriver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/2.0/xpan/file" {
			t.Errorf("unexpected path %s", r.URL.Path)
			return
		}
		start := r.URL.Query().Get("start")
		starts = append(starts, start)
		list := []map[string]any{}
		if start == "0" {
			for i := 0; i < dirListNum; i++ {
				list = append(list, map[string]any{
					"path": "/panrouter_tmp/f" + itoa(i), "server_mtime": time.Now().Unix(),
				})
			}
		} else {
			list = append(list, map[string]any{
				"path": "/panrouter_tmp/last.bin", "server_mtime": time.Now().Unix(),
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0, "list": list})
	}))

	entries, complete, err := d.listDir(context.Background(), cred().Cookie, "/panrouter_tmp")
	if err != nil {
		t.Fatalf("listDir: %v", err)
	}
	if !complete {
		t.Fatal("不满一页即到底,complete 应为 true")
	}
	if len(entries) != dirListNum+1 {
		t.Fatalf("翻页后应拿到 %d 条, got %d", dirListNum+1, len(entries))
	}
	if len(starts) != 2 || starts[0] != "0" || starts[1] != itoa(dirListNum) {
		t.Fatalf("翻页 start 序列不对: %v", starts)
	}
}

// 复用命中即续租:否则「正在取链」的副本会被并发清扫判成闲置并删掉。
func TestReuseCopyLeasesOnHit(t *testing.T) {
	d := newTestDriver(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"errno": 0})
	}))
	old := time.Now().Add(-copyTTL + time.Minute)
	d.rememberCopy(cred().Cookie, "12345", "111", copyEntry{
		fsid: "999", path: "/panrouter_tmp/a.bin", at: old,
	})
	if _, ok := d.reuseCopy(cred().Cookie, "12345", "111"); !ok {
		t.Fatal("未过期副本应命中复用")
	}
	if got := time.Since(d.ledgerAt(cred().Cookie, "12345", "111")); got > 2*time.Second {
		t.Fatalf("命中复用必须续租 at, 距现在 %v", got)
	}
}
