package pan123

import (
	"context"
	"encoding/base64"
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

// 合约测试:用 httptest 回放 123 云盘响应样本,不打真实网盘。
// 口径来自桌面端 MangoRouter Pan123Api(抓包实证):share/get 匿名、
// download/info 需 JWT+签名、DownloadURL 为 download-v2?params=<base64> 包装、
// CDN redirect_url JSON 跳转页需跟随。

func newTestDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	cl, err := httpx.New(httpx.Options{AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	d := New(cl)
	d.shareBase = srv.URL
	d.downloadBase = srv.URL
	return d
}

func writeJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}

const (
	shareListRoot = `{"code":0,"message":"ok","data":{"Expired":false,"Next":"-1","InfoList":[` +
		`{"FileId":101,"FileName":"movie.mp4","Size":1048576,"Type":0,"ParentFileId":0,"S3KeyFlag":"S3K1","Etag":"ET1","StorageNode":"SN1"},` +
		`{"FileId":102,"FileName":"sub","Size":0,"Type":1,"ParentFileId":0,"S3KeyFlag":"","Etag":"","StorageNode":""}]}}`
	shareListSub = `{"code":0,"message":"ok","data":{"Expired":false,"Next":"-1","InfoList":[` +
		`{"FileId":201,"FileName":"inner.txt","Size":42,"Type":0,"ParentFileId":102,"S3KeyFlag":"S3K2","Etag":"ET2","StorageNode":"SN2"}]}}`
	shareExpired = `{"code":0,"message":"ok","data":{"Expired":true,"Next":"-1","InfoList":[]}}`
)

// download-v2?params=<base64> 包装（URL-safe）;var 而非 const:函数调用结果非常量。
// 「CDN」URL 指向测试服务自身（final 路径不带 auto_redirect → 返回 FILE-CONTENT）。
var wrappedDownloadURL = "https://dl.123pan.cn/download-v2?params=" + b64("https://cdn.example.com/file.mp4?auto_redirect=0")

func b64(s string) string {
	return base64.URLEncoding.EncodeToString([]byte(s))
}

// mockServer:按路径分发上游响应;download/info 校验签名头与 JWT 存在。
func mockServer(t *testing.T, downloadBody string) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	downloadCalls := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/b/api/share/get"):
			q := r.URL.Query()
			if q.Get("shareKey") == "" {
				writeJSON(w, `{"code":400,"message":"缺少shareKey"}`)
				return
			}
			if q.Get("ParentFileId") == "102" {
				writeJSON(w, shareListSub)
				return
			}
			writeJSON(w, shareListRoot)
		case strings.Contains(r.URL.Path, "/b/api/share/download/info"):
			mu.Lock()
			downloadCalls++
			mu.Unlock()
			// 签名头与 JWT 必须存在（服务端契约:缺签名=未鉴权请求）
			if r.Header.Get("auth-key") == "" || r.Header.Get("auth-value") == "" {
				writeJSON(w, `{"code":401,"message":"token 无效或已过期"}`)
				return
			}
			if !strings.HasPrefix(r.Header.Get("authorization"), "Bearer ") {
				writeJSON(w, `{"code":401,"message":"token 无效或已过期"}`)
				return
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["ShareKey"] == "" || body["S3KeyFlag"] == "" {
				writeJSON(w, `{"code":400,"message":"参数错误"}`)
				return
			}
			writeJSON(w, downloadBody)
		case strings.Contains(r.URL.Path, "/b/api/user/info"):
			if r.Header.Get("auth-key") == "" {
				writeJSON(w, `{"code":401,"message":"token 无效或已过期"}`)
				return
			}
			writeJSON(w, `{"code":0,"message":"ok","data":{"Nickname":"tester"}}`)
		default:
			// CDN 直链或 redirect_url 探测
			if strings.Contains(r.URL.RawQuery, "auto_redirect=0") {
				writeJSON(w, `{"code":0,"data":{"redirect_url":"https://cdn2.example.com/final.mp4"}}`)
				return
			}
			w.WriteHeader(200)
			_, _ = w.Write([]byte("FILE-CONTENT"))
		}
	}))
}

func TestResolveShareFlatAndNested(t *testing.T) {
	srv := mockServer(t, wrappedDownloadURL)
	defer srv.Close()
	d := newTestDriver(t, srv)

	nodes, err := d.ResolveShare(context.Background(), driver.ShareLink{URL: "https://www.123pan.com/s/abc123-def456"}, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	var names []string
	for _, n := range nodes {
		names = append(names, n.Name)
	}
	// 根文件 + 子目录文件（递归展开,路径带目录前缀）
	want := []string{"movie.mp4", "sub/inner.txt"}
	if len(names) != len(want) {
		t.Fatalf("nodes = %v, want %v", names, want)
	}
	for i, w := range want {
		if names[i] != w {
			t.Fatalf("names = %v, want %v", names, want)
		}
	}
	// 文件节点必须带齐提链上下文
	n0 := nodes[0]
	if n0.Ext["s3key_flag"] != "S3K1" || n0.Ext["etag"] != "ET1" || n0.Ext["storage_node"] != "SN1" || n0.Ext["share_key"] != "abc123-def456" {
		t.Fatalf("ext = %v", n0.Ext)
	}
	if n0.Size != 1048576 {
		t.Fatalf("size = %d", n0.Size)
	}
}

func TestResolveShareExpired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, shareExpired)
	}))
	defer srv.Close()
	d := newTestDriver(t, srv)

	_, err := d.ResolveShare(context.Background(), driver.ShareLink{URL: "https://www.123pan.com/s/abc-def"}, nil)
	var de *driver.Error
	if !errors.As(err, &de) || de.Kind != driver.KindShareGone {
		t.Fatalf("err = %v, want KindShareGone", err)
	}
}

func TestResolveShareBadLink(t *testing.T) {
	srv := mockServer(t, wrappedDownloadURL)
	defer srv.Close()
	d := newTestDriver(t, srv)

	_, err := d.ResolveShare(context.Background(), driver.ShareLink{URL: "https://pan.baidu.com/s/1abc"}, nil)
	var de *driver.Error
	if !errors.As(err, &de) || de.Kind != driver.KindNotFound {
		t.Fatalf("err = %v, want KindNotFound", err)
	}
}

func TestGetDirectLinkRequiresCredential(t *testing.T) {
	srv := mockServer(t, wrappedDownloadURL)
	defer srv.Close()
	d := newTestDriver(t, srv)

	nodes, err := d.ResolveShare(context.Background(), driver.ShareLink{URL: "https://www.123pan.com/s/abc123-def456"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.GetDirectLink(context.Background(), nil, driver.FileRef{FID: nodes[0].FID, Ext: nodes[0].Ext})
	var de *driver.Error
	if !errors.As(err, &de) || de.Kind != driver.KindAuthExpired {
		t.Fatalf("err = %v, want KindAuthExpired", err)
	}
}

func TestGetDirectLinkHappyPath(t *testing.T) {
	// 完整跟随链:download/info → download-v2 wrap URL（decode 得 srv/file.mp4?auto_redirect=0）→
	// JSON redirect_url → srv/final.mp4（真实文件流,不再跟随）。「CDN」即测试服务自身。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/b/api/share/download/info"):
			writeJSON(w, `{"code":0,"message":"ok","data":{"DownloadURL":"`+wrappedLocalURL(r.Host)+`"}}`)
		case r.URL.Path == "/file.mp4":
			writeJSON(w, `{"code":0,"data":{"redirect_url":"`+"http://"+r.Host+`/final.mp4"}}`)
		default:
			_, _ = w.Write([]byte("FILE-CONTENT"))
		}
	}))
	defer srv.Close()
	d := newTestDriver(t, srv)

	cred := &driver.Credential{Cookie: "JWT-TOKEN"}
	link, err := d.GetDirectLink(context.Background(), cred, driver.FileRef{
		FID: "101", Ext: map[string]string{"share_key": "k", "s3key_flag": "S3K1", "etag": "E", "size": "1048576"},
	})
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	if link.URL != srv.URL+"/final.mp4" {
		t.Fatalf("url = %s, want final CDN", link.URL)
	}
	if link.Referer != downloadReferer {
		t.Fatalf("referer = %s", link.Referer)
	}
	if link.Cookie != "" {
		t.Fatalf("直链不应绑 Cookie（浏览器 302 才可用）: %s", link.Cookie)
	}
}

// wrappedLocalURL 生成指向测试服务自身的 download-v2 wrap URL。
func wrappedLocalURL(host string) string {
	return "http://" + host + "/download-v2?params=" + b64("http://"+host+"/file.mp4?auto_redirect=0")
}

func TestGetDirectLinkPlainURL(t *testing.T) {
	// 直链形态直给（无包装无 redirect）:原样返回。CDN 即测试服务自身（不带 auto_redirect → 文件流）。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/b/api/share/download/info") {
			writeJSON(w, `{"code":0,"message":"ok","data":{"DownloadURL":"http://`+r.Host+`/plain.mp4"}}`)
			return
		}
		_, _ = w.Write([]byte("FILE-CONTENT"))
	}))
	defer srv.Close()
	d := newTestDriver(t, srv)

	cred := &driver.Credential{Cookie: "JWT"}
	link, err := d.GetDirectLink(context.Background(), cred, driver.FileRef{
		FID: "101", Ext: map[string]string{"share_key": "k", "s3key_flag": "S", "etag": "E"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if link.URL != srv.URL+"/plain.mp4" {
		t.Fatalf("url = %s", link.URL)
	}
}

func TestGetDirectLinkAuthExpiredMapping(t *testing.T) {
	// 上游 401 文案「token 无效或已过期」→ KindAuthExpired（触发账号看门狗而非接口告警）
	srv := mockServer(t, `{"code":401,"message":"token 无效或已过期"}`)
	// mockServer 的 download 分支会先校验签名头再回业务响应——这里直接替换 handler
	srv.Close()
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, `{"code":401,"message":"token 无效或已过期"}`)
	}))
	defer srv2.Close()
	d := newTestDriver(t, srv2)

	_, err := d.GetDirectLink(context.Background(), &driver.Credential{Cookie: "JWT"}, driver.FileRef{
		FID: "101", Ext: map[string]string{"share_key": "k", "s3key_flag": "S", "etag": "E"},
	})
	var de *driver.Error
	if !errors.As(err, &de) || de.Kind != driver.KindAuthExpired {
		t.Fatalf("err = %v, want KindAuthExpired", err)
	}
}

func TestGetDirectLinkMissingContext(t *testing.T) {
	srv := mockServer(t, wrappedDownloadURL)
	defer srv.Close()
	d := newTestDriver(t, srv)

	_, err := d.GetDirectLink(context.Background(), &driver.Credential{Cookie: "JWT"}, driver.FileRef{FID: "1"})
	var de *driver.Error
	if !errors.As(err, &de) || de.Kind != driver.KindNotFound {
		t.Fatalf("err = %v, want KindNotFound", err)
	}
}

func TestCheckCredential(t *testing.T) {
	srv := mockServer(t, wrappedDownloadURL)
	defer srv.Close()
	d := newTestDriver(t, srv)

	st, err := d.CheckCredential(context.Background(), driver.Credential{Cookie: "JWT"})
	if err != nil || !st.Valid || st.Nickname != "tester" {
		t.Fatalf("status = %+v err = %v", st, err)
	}
}

// 生产实证(2026-11-21):参数合法的假 shareKey 上游恒回 code 5103「此分享不存在」,
// 稳定复现无风控 → 必须映射 KindShareGone(确定性终态),而非 KindUpstream(502+
// 计入熔断)——否则一次手滑链接就把整条 pan 通道打入 10min 熔断(v2.17 首日事故)。
func TestShareNotExistMapsShareGone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, `{"code":5103,"message":"此分享不存在","data":null}`)
	}))
	defer srv.Close()
	d := newTestDriver(t, srv)

	_, err := d.ResolveShare(context.Background(), driver.ShareLink{URL: "https://www.123pan.com/s/aaaaaa-bbbbbb"}, nil)
	var de *driver.Error
	if !errors.As(err, &de) || de.Kind != driver.KindShareGone {
		t.Fatalf("err = %v, want KindShareGone", err)
	}
}

// 400「ShareKey长度异常」是确定性请求错误 → KindNotFound,不触发熔断。
func TestShareBadKeyMapsNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, `{"code":400,"message":"ShareKey长度异常","data":null}`)
	}))
	defer srv.Close()
	d := newTestDriver(t, srv)

	_, err := d.ResolveShare(context.Background(), driver.ShareLink{URL: "https://www.123pan.com/s/xxxx"}, nil)
	var de *driver.Error
	if !errors.As(err, &de) || de.Kind != driver.KindNotFound {
		t.Fatalf("err = %v, want KindNotFound", err)
	}
}

// 其余未知业务码保持 KindUpstream（真实上游故障仍走 502+熔断路径）。
func TestUnknownCodeStaysUpstream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, `{"code":9999,"message":"内部异常","data":null}`)
	}))
	defer srv.Close()
	d := newTestDriver(t, srv)

	_, err := d.ResolveShare(context.Background(), driver.ShareLink{URL: "https://www.123pan.com/s/aaaaaa-bbbbbb"}, nil)
	var de *driver.Error
	if !errors.As(err, &de) || de.Kind != driver.KindUpstream {
		t.Fatalf("err = %v, want KindUpstream", err)
	}
}

func TestSignDeterminism(t *testing.T) {
	// 同 ts 两次签名 auth-key 必须一致（时间部分确定性）,auth-value 因 random 不同而不同
	ak1, av1 := makeSign("/b/api/share/download/info", 1700000000)
	ak2, _ := makeSign("/b/api/share/download/info", 1700000000)
	if ak1 != ak2 {
		t.Fatalf("auth-key not deterministic: %s vs %s", ak1, ak2)
	}
	if !strings.Contains(av1, "1700000000-") {
		t.Fatalf("auth-value = %s", av1)
	}
}

func TestDecodeDownloadURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://dl.123pan.cn/download-v2?params=" + b64("https://cdn.example.com/a.mp4"), "https://cdn.example.com/a.mp4"},
		{b64("https://cdn.example.com/b.mp4"), "https://cdn.example.com/b.mp4"},
		{"https://cdn.example.com/plain.mp4", ""}, // 已是 URL 形态且无 params → 原样由调用方兜底
	}
	for _, c := range cases {
		if got := decodeDownloadURL(c.in); got != c.want {
			t.Errorf("decode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestShareWalkBudgetTruncates(t *testing.T) {
	// 超大目录树触发预算截断:末节点带 truncated 标记而非死循环（生成 300 个文件 > maxShareFiles=200）
	var bigList strings.Builder
	bigList.WriteString(`{"code":0,"message":"ok","data":{"Expired":false,"Next":"-1","InfoList":[`)
	for i := 0; i < 300; i++ {
		if i > 0 {
			bigList.WriteString(",")
		}
		fmt.Fprintf(&bigList, `{"FileId":%d,"FileName":"f%d","Size":1,"Type":0,"ParentFileId":0,"S3KeyFlag":"K%d","Etag":"E","StorageNode":""}`, i, i, i)
	}
	bigList.WriteString("]}}")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, bigList.String())
	}))
	defer srv.Close()
	d := newTestDriver(t, srv)

	nodes, err := d.ResolveShare(context.Background(), driver.ShareLink{URL: "https://www.123pan.com/s/abc-def"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != maxShareFiles {
		t.Fatalf("nodes = %d, want budget cap %d", len(nodes), maxShareFiles)
	}
	if nodes[len(nodes)-1].Ext["truncated"] != "1" {
		t.Fatalf("last node missing truncated flag: %v", nodes[len(nodes)-1].Ext)
	}
}
