package c139

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dengyie/panrouter/internal/driver"
	"github.com/dengyie/panrouter/internal/pkg/httpx"
)

// 合约测试:httptest 回放 139 响应样本(加密体),不打真实网盘。
// 口径对齐桌面端 MangoRouter C139Api.kt:getOutLinkInfoV6 匿名(caLst+coLst)、
// dlFromOutLinkV3 登录态 → redrUrl、配额端点校验凭据。

func newTestDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	cl, err := httpx.New(httpx.Options{AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	d := New(cl, srv.URL)
	d.quota = srv.URL + "/user/disk/quota/detail"
	return d
}

// encBody 用共享 key 加密样本(测试侧模拟 139 网关响应形态)。
func encBody(t *testing.T, plaintext string) string {
	t.Helper()
	enc, err := encryptBody(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func decReq(t *testing.T, r *http.Request) string {
	t.Helper()
	raw, _ := io.ReadAll(r.Body)
	plain, err := decryptBody(string(raw))
	if err != nil {
		t.Fatalf("decrypt request: %v", err)
	}
	return plain
}

const (
	shareListRoot = `{"resultCode":"0","success":true,"data":{` +
		`"caLst":[{"caID":"C100","caName":"sub","isdir":true}],` +
		`"coLst":[{"coID":"F200","coName":"movie.mp4","coSize":1048576,"coType":1}]}}`
	shareListSub = `{"resultCode":"0","success":true,"data":{` +
		`"caLst":[],"coLst":[{"coID":"F201","coName":"inner.txt","coSize":42,"coType":1}]}}`
	shareGoneBody  = `{"resultCode":"10003","success":false,"desc":"分享不存在"}`
	shareLinkBody  = `{"resultCode":"0","success":true,"data":{"redrUrl":"https://obs.139.com/s3file?sig=abc","coSize":1048576}}`
	quotaOKBody    = `{"success":true,"code":"0000","message":"ok","data":{"diskSize":30720}}`
	quotaFailBody  = `{"success":false,"code":"04000005","message":"认证失败"}`
)

func mockServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 139 网关契约:分享通道 hcy-cool-flag 必带(缺它业务层拿不到明文 → 9530);
		// 个人云盘管理通道(cloudPost/quota)不加密,不需要该开关。
		if strings.Contains(r.URL.Path, "/yun-share/") && r.Header.Get("hcy-cool-flag") != "1" {
			w.WriteHeader(400)
			_, _ = w.Write([]byte("missing cool-flag"))
			return
		}
		switch {
		case strings.Contains(r.URL.Path, "getOutLinkInfoV6"):
			plain := decReq(t, r)
			var req struct {
				GetOutLinkInfoReq struct {
					LinkID string `json:"linkID"`
					PCaID  string `json:"pCaID"`
				} `json:"getOutLinkInfoReq"`
			}
			if err := json.Unmarshal([]byte(plain), &req); err != nil {
				t.Errorf("list req: %v", err)
			}
			// 列表端点 account 必须为空串(桌面端 §3 实证)
			if !strings.Contains(plain, `"account":""`) {
				t.Errorf("list account must be empty: %s", plain)
			}
			if req.GetOutLinkInfoReq.PCaID == "C100" {
				writeJSON(w, encBody(t, shareListSub))
				return
			}
			writeJSON(w, encBody(t, shareListRoot))
		case strings.Contains(r.URL.Path, "dlFromOutLinkV3"):
			plain := decReq(t, r)
			// 取链必须带 Authorization 与账号字段(登录态)
			if r.Header.Get("Authorization") == "" {
				writeJSON(w, encBody(t, `{"resultCode":"04000005","success":false,"desc":"认证失败"}`))
				return
			}
			if !strings.Contains(plain, `"account":"13800000000"`) {
				t.Errorf("download req account: %s", plain)
			}
			writeJSON(w, encBody(t, shareLinkBody))
		case strings.Contains(r.URL.Path, "quota/detail"):
			if r.Header.Get("mcloud-sign") == "" || r.Header.Get("Authorization") == "" {
				writeJSON(w, `{"success":false,"code":"04000005","message":"认证失败"}`)
				return
			}
			writeJSON(w, quotaOKBody)
		default:
			w.WriteHeader(404)
		}
	}))
}

func writeJSON(w http.ResponseWriter, body string) {
	_, _ = w.Write([]byte(body))
}

func TestResolveShareFlatAndNested(t *testing.T) {
	srv := mockServer(t)
	defer srv.Close()
	d := newTestDriver(t, srv)

	nodes, err := d.ResolveShare(context.Background(), driver.ShareLink{
		URL: "https://yun.139.com/shareweb/#/w/i/abcdEFGH",
	}, nil)
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
	if nodes[0].Ext["link_id"] != "abcdEFGH" {
		t.Fatalf("ext = %v", nodes[0].Ext)
	}
	if nodes[0].Size != 1048576 {
		t.Fatalf("size = %d", nodes[0].Size)
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

func TestResolveShareGone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, encBody(t, shareGoneBody))
	}))
	defer srv.Close()
	d := newTestDriver(t, srv)

	_, err := d.ResolveShare(context.Background(), driver.ShareLink{URL: "https://yun.139.com/shareweb/#/w/i/gone123"}, nil)
	var de *driver.Error
	if !errors.As(err, &de) || de.Kind != driver.KindShareGone {
		t.Fatalf("err = %v, want KindShareGone", err)
	}
}

func TestGetDirectLinkRequiresCredential(t *testing.T) {
	srv := mockServer(t)
	defer srv.Close()
	d := newTestDriver(t, srv)

	_, err := d.GetDirectLink(context.Background(), nil, driver.FileRef{FID: "F200", Ext: map[string]string{"link_id": "abc"}})
	var de *driver.Error
	if !errors.As(err, &de) || de.Kind != driver.KindAuthExpired {
		t.Fatalf("err = %v, want KindAuthExpired", err)
	}
}

func TestGetDirectLinkHappyPath(t *testing.T) {
	srv := mockServer(t)
	defer srv.Close()
	d := newTestDriver(t, srv)

	cred := &driver.Credential{Cookie: "authorization=Basic " + base64.StdEncoding.EncodeToString([]byte("pc:13800000000:tk")) + "; other=1"}
	link, err := d.GetDirectLink(context.Background(), cred, driver.FileRef{FID: "F200", Ext: map[string]string{"link_id": "abcdEFGH"}})
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	if link.URL != "https://obs.139.com/s3file?sig=abc" {
		t.Fatalf("url = %s", link.URL)
	}
	if link.Cookie != "" {
		t.Fatalf("OBS 签名直链不绑 Cookie: %s", link.Cookie)
	}
}

func TestCheckCredential(t *testing.T) {
	srv := mockServer(t)
	defer srv.Close()
	d := newTestDriver(t, srv)

	cred := driver.Credential{Cookie: "authorization=Basic " + base64.StdEncoding.EncodeToString([]byte("pc:13800000000:tk")) + "; skey=SK"}
	st, err := d.CheckCredential(context.Background(), cred)
	if err != nil || !st.Valid || st.Nickname != "13800000000" {
		t.Fatalf("status = %+v err = %v", st, err)
	}
	// 缺 authorization → invalid 不报错
	st2, err := d.CheckCredential(context.Background(), driver.Credential{Cookie: "foo=bar"})
	if err != nil || st2.Valid {
		t.Fatalf("no-auth status = %+v err = %v", st2, err)
	}
}

func TestCalSignDeterminism(t *testing.T) {
	// 同 ts/rand 两次签名一致;签名 32 位大写 hex
	s1 := calSign(`{"a":1}`, "2026-11-21 12:00:00", "abcdef0123456789")
	s2 := calSign(`{"a":1}`, "2026-11-21 12:00:00", "abcdef0123456789")
	if s1 != s2 || len(s1) != 32 || s1 != strings.ToUpper(s1) {
		t.Fatalf("sign = %s vs %s", s1, s2)
	}
	// body 变化签名变化
	if calSign(`{"a":2}`, "2026-11-21 12:00:00", "abcdef0123456789") == s1 {
		t.Fatal("sign should differ with body")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plain := `{"getOutLinkInfoReq":{"linkID":"abc"}}`
	enc, err := encryptBody(plain)
	if err != nil {
		t.Fatal(err)
	}
	// IV 前置:两次加密密文不同(随机 IV)
	enc2, _ := encryptBody(plain)
	if enc == enc2 {
		t.Fatal("random IV expected")
	}
	got, err := decryptBody(enc)
	if err != nil || got != plain {
		t.Fatalf("roundtrip = %q err = %v", got, err)
	}
}

func TestDecryptGzipFallback(t *testing.T) {
	// 解密后 gzip 魔数先解压(桌面端/alist YunCrypto 同款)
	var buf strings.Builder
	gz := newGzipWriter(&buf)
	gz.Write([]byte("hello-gzip"))
	gz.Close()
	// 手工构造:IV(16) + gzip 加密体
	enc := encBody(t, buf.String())
	got, err := decryptBody(enc)
	if err != nil || got != "hello-gzip" {
		t.Fatalf("gzip roundtrip = %q err = %v", got, err)
	}
}

func TestShareWalkBudgetTruncates(t *testing.T) {
	// 生成 300 个文件 > maxShareFiles=200 → 截断标记
	var items strings.Builder
	items.WriteString(`{"resultCode":"0","success":true,"data":{"caLst":[],"coLst":[`)
	for i := 0; i < 300; i++ {
		if i > 0 {
			items.WriteString(",")
		}
		items.WriteString(`{"coID":"F` + itoa(i) + `","coName":"f` + itoa(i) + `.mp4","coSize":1,"coType":1}`)
	}
	items.WriteString("]}}")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, encBody(t, items.String()))
	}))
	defer srv.Close()
	d := newTestDriver(t, srv)

	nodes, err := d.ResolveShare(context.Background(), driver.ShareLink{URL: "https://yun.139.com/shareweb/#/w/i/big123"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != maxShareFiles {
		t.Fatalf("nodes = %d, want cap %d", len(nodes), maxShareFiles)
	}
	if nodes[len(nodes)-1].Ext["truncated"] != "1" {
		t.Fatal("missing truncated flag")
	}
}

func itoa(i int) string {
	return json.Number(jsonInt(i)).String()
}

func jsonInt(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func newGzipWriter(buf *strings.Builder) *gzip.Writer {
	return gzip.NewWriter(&stringWriter{buf})
}

type stringWriter struct{ b *strings.Builder }

func (w *stringWriter) Write(p []byte) (int, error) { return w.b.Write(p) }
func (w *stringWriter) WriteString(s string) (int, error) { return w.b.WriteString(s) }
