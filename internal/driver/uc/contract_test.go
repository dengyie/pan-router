package uc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/dengyie/panrouter/internal/driver"
	"github.com/dengyie/panrouter/internal/pkg/httpx"
)

// 合约测试:httptest 回放 UC 响应样本,不打真实网盘。
// 口径对齐桌面端 MangoRouter UCApi.kt:token→stoken、v2/detail(detail_info.list +
// share_fid_token)、file/download?entry=ft 游客取链(__pugs 同响应绑定)。

func newTestDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	cl, err := httpx.New(httpx.Options{AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	d := New(cl, srv.URL)
	d.info = srv.URL + "/account/info"
	return d
}

func writeJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}

const (
	tokenBody = `{"code":0,"status":200,"message":"ok","data":{"stoken":"STOKEN","title":"uc-share","first_fid":"101"}}`
	// v2/detail 根:一文件一目录;列表在 detail_info.list
	detailRoot = `{"code":0,"status":200,"message":"ok","data":{"detail_info":{"list":[` +
		`{"fid":"101","file_name":"movie.mp4","size":1048576,"dir":false,"pdir_fid":"0","share_fid_token":"FT1"},` +
		`{"fid":"102","file_name":"sub","size":0,"dir":true,"pdir_fid":"0","share_fid_token":""}]}}}`
	detailSub = `{"code":0,"status":200,"message":"ok","data":{"detail_info":{"list":[` +
		`{"fid":"201","file_name":"inner.txt","size":42,"dir":false,"pdir_fid":"102","share_fid_token":"FT2"}]}}}`
	downloadBody = `{"code":0,"status":200,"message":"ok","data":[{"fid":"101","file_name":"movie.mp4","download_url":"https://dl.uc.cn/file.mp4","size":1048576}]}`
)

// mockServer 回放 UC 全链端点;download 校验游客 UA 与 body 形态。
func mockServer(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	downloadCalls := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/share/sharepage/token"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["pwd_id"] == "" {
				writeJSON(w, `{"code":400,"message":"缺少 pwd_id"}`)
				return
			}
			writeJSON(w, tokenBody)
		case strings.Contains(r.URL.Path, "/share/sharepage/v2/detail"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if fid, _ := body["pdir_fid"].(string); fid == "102" {
				writeJSON(w, detailSub)
				return
			}
			writeJSON(w, detailRoot)
		case strings.Contains(r.URL.Path, "/file/download"):
			mu.Lock()
			downloadCalls++
			mu.Unlock()
			// 游客链路必须用 uc-cloud-drive UA(桌面端实证:风控更严)
			if !strings.Contains(r.Header.Get("User-Agent"), "uc-cloud-drive") {
				writeJSON(w, `{"code":-1,"message":"UA 不对"}`)
				return
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["pwd_id"] == "" || body["stoken"] == "" {
				writeJSON(w, `{"code":400,"message":"参数错误"}`)
				return
			}
			// 游客态响应必须下发 __pugs(与直链同响应绑定)
			w.Header().Set("Set-Cookie", "__pugs=PUGS-VALUE; Path=/; Domain=uc.cn")
			writeJSON(w, downloadBody)
		case strings.Contains(r.URL.Path, "/account/info"):
			if r.Header.Get("Cookie") == "" {
				w.WriteHeader(401)
				return
			}
			writeJSON(w, `{"success":true,"data":{"nickname":"uctester"}}`)
		default:
			// 直链 CDN 探测
			w.WriteHeader(200)
			_, _ = w.Write([]byte("FILE-CONTENT"))
		}
	}))
}

func TestResolveShareFlatAndNested(t *testing.T) {
	srv := mockServer(t)
	defer srv.Close()
	d := newTestDriver(t, srv)

	nodes, err := d.ResolveShare(context.Background(), driver.ShareLink{URL: "https://drive.uc.cn/s/abc123"}, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	want := []string{"movie.mp4", "sub/inner.txt"}
	var names []string
	for _, n := range nodes {
		names = append(names, n.Name)
	}
	if len(names) != len(want) {
		t.Fatalf("names = %v, want %v", names, want)
	}
	for i, w := range want {
		if names[i] != w {
			t.Fatalf("names = %v, want %v", names, want)
		}
	}
	// 文件节点带齐提链上下文(stoken/pwd_id/fid_token)
	n0 := nodes[0]
	if n0.Ext["pwd_id"] != "abc123" || n0.Ext["stoken"] != "STOKEN" || n0.Ext["fid_token"] != "FT1" {
		t.Fatalf("ext = %v", n0.Ext)
	}
	if n0.Size != 1048576 {
		t.Fatalf("size = %d", n0.Size)
	}
}

func TestResolveShareBadLink(t *testing.T) {
	srv := mockServer(t)
	defer srv.Close()
	d := newTestDriver(t, srv)

	_, err := d.ResolveShare(context.Background(), driver.ShareLink{URL: "https://pan.baidu.com/s/1abc"}, nil)
	var de *driver.Error
	if !errors.As(err, &de) || de.Kind != driver.KindNotFound {
		t.Fatalf("err = %v, want KindNotFound", err)
	}
}

func TestGuestDirectLink(t *testing.T) {
	// 游客链路:cred=nil → uc-cloud-drive UA + __pugs 捕获绑定直链
	srv := mockServer(t)
	defer srv.Close()
	d := newTestDriver(t, srv)

	nodes, err := d.ResolveShare(context.Background(), driver.ShareLink{URL: "https://drive.uc.cn/s/abc123"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	link, err := d.GetDirectLink(context.Background(), nil, driver.FileRef{FID: nodes[0].FID, Ext: nodes[0].Ext})
	if err != nil {
		t.Fatalf("guest link: %v", err)
	}
	if link.URL != "https://dl.uc.cn/file.mp4" {
		t.Fatalf("url = %s", link.URL)
	}
	if link.Cookie != "__pugs=PUGS-VALUE" {
		t.Fatalf("cookie = %q, want __pugs=PUGS-VALUE", link.Cookie)
	}
	if !strings.Contains(link.UA, "uc-cloud-drive") {
		t.Fatalf("直链 UA 应为 uc-cloud-drive 客户端: %s", link.UA)
	}
}

func TestGuestPugsCached(t *testing.T) {
	// 第二次游客取链复用缓存的 __pugs(不带账号 Cookie 也带缓存令牌)
	srv := mockServer(t)
	defer srv.Close()
	d := newTestDriver(t, srv)

	ext := map[string]string{"pwd_id": "p", "stoken": "s", "fid_token": "ft"}
	if _, err := d.GetDirectLink(context.Background(), nil, driver.FileRef{FID: "1", Ext: ext}); err != nil {
		t.Fatal(err)
	}
	d.pugsMu.Lock()
	cached := d.guestPugs
	d.pugsMu.Unlock()
	if cached != "__pugs=PUGS-VALUE" {
		t.Fatalf("guestPugs 缓存 = %q", cached)
	}
}

func TestDirectLinkRequiresLoginFor31001(t *testing.T) {
	// 31001 → KindAuthExpired(桌面端错误码表:该分享需要登录后才能下载)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, `{"code":31001,"status":400,"message":"需要登录"}`)
	}))
	defer srv.Close()
	d := newTestDriver(t, srv)

	ext := map[string]string{"pwd_id": "p", "stoken": "s", "fid_token": "ft"}
	_, err := d.GetDirectLink(context.Background(), nil, driver.FileRef{FID: "1", Ext: ext})
	var de *driver.Error
	if !errors.As(err, &de) || de.Kind != driver.KindAuthExpired {
		t.Fatalf("err = %v, want KindAuthExpired", err)
	}
}

func TestShareGoneMapping(t *testing.T) {
	// 14001 → KindShareGone(分享已失效或提取码有误)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, `{"code":14001,"status":400,"message":"分享已失效"}`)
	}))
	defer srv.Close()
	d := newTestDriver(t, srv)

	_, err := d.ResolveShare(context.Background(), driver.ShareLink{URL: "https://drive.uc.cn/s/abc123"}, nil)
	var de *driver.Error
	if !errors.As(err, &de) || de.Kind != driver.KindShareGone {
		t.Fatalf("err = %v, want KindShareGone", err)
	}
}

// 生产实证(2026-11-21):假 pwd_id 上游恒回 code 41006「分享不存在」(status 404,
// 确定性终态)→ 必须映射 KindShareGone 而非 KindUpstream——否则 502+计入熔断
// (pan123 v2.17.1 同型事故,口径统一:确定性终态不计熔断)。
func TestShareNotExist41006MapsShareGone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, `{"status":404,"code":41006,"message":"分享不存在"}`)
	}))
	defer srv.Close()
	d := newTestDriver(t, srv)

	_, err := d.ResolveShare(context.Background(), driver.ShareLink{URL: "https://drive.uc.cn/s/aaaaaaaa"}, nil)
	var de *driver.Error
	if !errors.As(err, &de) || de.Kind != driver.KindShareGone {
		t.Fatalf("err = %v, want KindShareGone", err)
	}
}

func TestCheckCredential(t *testing.T) {
	srv := mockServer(t)
	defer srv.Close()
	d := newTestDriver(t, srv)

	st, err := d.CheckCredential(context.Background(), driver.Credential{Cookie: "__pus=a; __puus=b"})
	if err != nil || !st.Valid || st.Nickname != "uctester" {
		t.Fatalf("status = %+v err = %v", st, err)
	}
	// 空 Cookie → invalid 不报错
	st2, err := d.CheckCredential(context.Background(), driver.Credential{})
	if err != nil || st2.Valid {
		t.Fatalf("empty cookie: status = %+v err = %v", st2, err)
	}
}

func TestWalkBudgetTruncates(t *testing.T) {
	// 300 个文件 > maxShareFiles=200,触发截断标记
	var bigList strings.Builder
	bigList.WriteString(`{"code":0,"status":200,"message":"ok","data":{"detail_info":{"list":[`)
	for i := 0; i < 300; i++ {
		if i > 0 {
			bigList.WriteString(",")
		}
		fmt.Fprintf(&bigList, `{"fid":"f%d","file_name":"f%d.mp4","size":1,"dir":false,"share_fid_token":"T%d"}`, i, i, i)
	}
	bigList.WriteString("]}}}")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/share/sharepage/token"):
			writeJSON(w, tokenBody)
		case strings.Contains(r.URL.Path, "/share/sharepage/v2/detail"):
			writeJSON(w, bigList.String())
		default:
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()
	d := newTestDriver(t, srv)

	nodes, err := d.ResolveShare(context.Background(), driver.ShareLink{URL: "https://drive.uc.cn/s/abc123"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != maxShareFiles {
		t.Fatalf("nodes = %d, want cap %d", len(nodes), maxShareFiles)
	}
	if nodes[len(nodes)-1].Ext["truncated"] != "1" {
		t.Fatalf("last node missing truncated flag")
	}
}
