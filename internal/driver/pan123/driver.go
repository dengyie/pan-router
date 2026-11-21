// Package pan123 实现 123 云盘 driver（分享解析 + 直链提链）。
//
// 接口口径完全对齐姊妹桌面端 MangoRouter 生产在用的 Pan123Api（抓包实证）：
//   - 分享列表 GET https://yun.123pan.cn/b/api/share/get —— 匿名、无签名；
//   - 分享下载 POST https://www.123865.com/b/api/share/download/info —— 需登录 JWT + auth-key/auth-value 签名头；
//   - 直链是 download-v2?params=<base64> 包装或整段 base64，解码后还得跟随 CDN 的
//     JSON redirect_url（auto_redirect=0）才是最终可下载地址；
//   - 下载直链必须带 Referer: https://yun.123pan.cn/。
//
// 网页私有接口改版只调整本包。签名算法见 sign.go（CRC32 派生，§6 抓包逐字还原）。
package pan123

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dengyie/panrouter/internal/driver"
	"github.com/dengyie/panrouter/internal/pkg/httpx"
)

const (
	shareGetBase      = "https://yun.123pan.cn"  // 分享列表（匿名）
	shareDownloadBase = "https://www.123865.com" // 分享下载信息（登录+签名）
	dartUA            = "Dart/3.12 (dart:io)"
	webUA             = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
	downloadReferer   = "https://yun.123pan.cn/"
	downloadLinkTTL   = 1 * time.Hour
	// 分享目录遍历上界（与 quark 同口径）：防异常响应或超大分享拖死解析。
	maxShareDepth = 8
	maxShareFiles = 200
	maxShareDirs  = 64
	// CDN redirect_url 最大跟随跳数（桌面端同款：JSON 跳转页可能多跳）。
	maxRedirectFollows = 5
)

// 分享链接形态（桌面端 ShareLinkParser 同口径）：
//   - https://www.123pan.com/s/<ShareKey>（ShareKey 形如 abc123-456，两段用 - 连接）
//   - https://www.123865.com/s/<ShareKey>
//   - https://<UID>.share.123pan.cn/123pan/<ShareKey>
var shareKeyRes = []*regexp.Regexp{
	regexp.MustCompile(`123(?:865|pan)\.(?:com|cn)/s/([A-Za-z0-9]+-[A-Za-z0-9]+)`),
	regexp.MustCompile(`share\.123pan\.cn/123pan/([A-Za-z0-9-]+)`),
}

type Driver struct {
	client *httpx.Client
	// shareBase / downloadBase 供测试注入 httptest 地址;空 = 生产域名。
	shareBase    string
	downloadBase string
}

func New(client *httpx.Client) *Driver { return &Driver{client: client} }

// apiURL 取请求基准：测试注入时全部走同一 httptest 地址,生产按用途分域。
func (d *Driver) apiURL(base, path string) string {
	if d.shareBase != "" {
		return d.shareBase + path
	}
	return base + path
}

func (d *Driver) ID() string { return "pan123" }

// ---- 上游响应结构（只解用到的字段） ----

type apiFile struct {
	FileID       json.Number `json:"FileId"`
	FileName     string      `json:"FileName"`
	Size         int64       `json:"Size"`
	Type         int         `json:"Type"` // 1=目录
	ParentFileID json.Number `json:"ParentFileId"`
	S3KeyFlag    string      `json:"S3KeyFlag"`
	Etag         string      `json:"Etag"`
	StorageNode  string      `json:"StorageNode"`
}

type shareListResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Expired  bool      `json:"Expired"`
		Next     string    `json:"Next"` // "-1"=没有下一页；""=还有下一页；数字=游标
		InfoList []apiFile `json:"InfoList"`
	} `json:"data"`
}

type downloadInfoResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		DownloadURL string `json:"DownloadURL"`
	} `json:"data"`
}

// ---- FileNode.Ext 私有上下文键 ----

const (
	extS3KeyFlag   = "s3key_flag"
	extEtag        = "etag"
	extStorageNode = "storage_node"
	extShareKey    = "share_key"
	extPwd         = "pwd"
)

func (d *Driver) ResolveShare(ctx context.Context, share driver.ShareLink, cred *driver.Credential) ([]driver.FileNode, error) {
	key := extractShareKey(share.URL)
	if key == "" {
		return nil, driver.NewErr(driver.KindNotFound, "无法识别的 123 云盘分享链接", nil)
	}
	ext := map[string]string{extShareKey: key}
	if share.Pwd != "" {
		ext[extPwd] = share.Pwd
	}
	budget := &walkBudget{files: maxShareFiles, dirs: maxShareDirs}
	nodes, err := d.walkShare(ctx, cred, key, share.Pwd, "0", "", 0, ext, map[string]struct{}{}, budget)
	if err != nil {
		return nil, err
	}
	if budget.truncated {
		if len(nodes) == 0 {
			nodes = []driver.FileNode{{Ext: map[string]string{"truncated": "1"}}}
		} else {
			last := &nodes[len(nodes)-1]
			if last.Ext == nil {
				last.Ext = map[string]string{}
			}
			last.Ext["truncated"] = "1"
		}
	}
	return nodes, nil
}

func extractShareKey(rawURL string) string {
	for _, re := range shareKeyRes {
		if m := re.FindStringSubmatch(rawURL); m != nil {
			return m[1]
		}
	}
	return ""
}

type walkBudget struct {
	files     int
	dirs      int
	truncated bool
}

// walkShare 递归列出分享目录（parentFileId=0 为根）。123 的 Next 是字符串游标：
// "-1" 无下一页、"" 还有下一页、数字为断点续翻游标（桌面端实测口径）。
func (d *Driver) walkShare(ctx context.Context, cred *driver.Credential, key, pwd, parentFileID, prefix string, depth int, baseExt map[string]string, seen map[string]struct{}, bud *walkBudget) ([]driver.FileNode, error) {
	if depth > maxShareDepth {
		return nil, nil
	}
	if _, dup := seen[parentFileID]; dup {
		return nil, nil // 环防御：上游把父 ID 回指已访问目录时不死循环
	}
	seen[parentFileID] = struct{}{}
	bud.dirs--
	if bud.dirs < 0 {
		bud.truncated = true
		return nil, nil
	}

	var nodes []driver.FileNode
	next := "0"
	for page := 1; page <= 100; page++ {
		if err := ctx.Err(); err != nil {
			return nil, driver.NewErr(driver.KindUpstream, "123 分享目录遍历已取消", err)
		}
		q := url.Values{}
		q.Set("limit", "100")
		q.Set("next", next)
		q.Set("orderBy", "file_name")
		q.Set("orderDirection", "asc")
		q.Set("shareKey", key)
		q.Set("ParentFileId", parentFileID)
		q.Set("Page", strconv.Itoa(page))
		if pwd != "" {
			q.Set("SharePwd", pwd) // ⚠️ 无提取码时不传：传空值会 400「请输入Next」
		}
		var resp shareListResp
		if _, err := d.getJSON(ctx, d.apiURL(shareGetBase, "/b/api/share/get")+"?"+q.Encode(), map[string]string{
			"User-Agent": dartUA,
			"Referer":    downloadReferer,
		}, &resp); err != nil {
			return nil, err
		}
		if err := checkCode(resp.Code, resp.Message, "123 分享列表"); err != nil {
			return nil, err
		}
		if resp.Data.Expired {
			return nil, driver.NewErr(driver.KindShareGone, "123 云盘分享已失效", nil)
		}
		for _, f := range resp.Data.InfoList {
			name := f.FileName
			path := name
			if prefix != "" {
				path = prefix + "/" + name
			}
			if f.Type == 1 {
				bud.files--
				if bud.files < 0 {
					bud.truncated = true
					return nodes, nil
				}
				sub, err := d.walkShare(ctx, cred, key, pwd, f.FileID.String(), path, depth+1, baseExt, seen, bud)
				if err != nil {
					return nil, err
				}
				nodes = append(nodes, sub...)
				continue
			}
			bud.files--
			if bud.files < 0 {
				bud.truncated = true
				return nodes, nil
			}
			ext := map[string]string{
				extShareKey:    key,
				extS3KeyFlag:   f.S3KeyFlag,
				extEtag:        f.Etag,
				extStorageNode: f.StorageNode,
			}
			if pwd != "" {
				ext[extPwd] = pwd
			}
			nodes = append(nodes, driver.FileNode{
				FID:   f.FileID.String(),
				Name:  path,
				Size:  f.Size,
				IsDir: false,
				Ext:   ext,
			})
		}
		next = resp.Data.Next
		if next == "-1" || (next == "" && len(resp.Data.InfoList) == 0) {
			break
		}
		if next == "" {
			// "" 表示还有下一页但服务端没给游标：按 Page 翻页即可，next 维持 "0" 会从头拿导致死循环，
			// 123 的分页以 Page 为主、next 为断点续翻游标；继续下一页。
			next = "0"
		}
	}
	return nodes, nil
}

// ---- 直链 ----

func (d *Driver) GetDirectLink(ctx context.Context, cred *driver.Credential, ref driver.FileRef) (driver.DirectLink, error) {
	if ref.Own {
		return driver.DirectLink{}, driver.NewErr(driver.KindUnsupported, "123 云盘暂不支持网盘内文件提链（分享解析已可用）", nil)
	}
	key := ref.Ext[extShareKey]
	if key == "" {
		return driver.DirectLink{}, driver.NewErr(driver.KindNotFound, "缺少 123 分享上下文,请重新解析", nil)
	}
	if cred == nil || cred.Cookie == "" {
		return driver.DirectLink{}, driver.NewErr(driver.KindAuthExpired, "123 分享直链需要登录态,请先在「账号管理」添加 123 账号（账号密码登录获取 JWT）", nil)
	}
	s3KeyFlag := ref.Ext[extS3KeyFlag]
	etag := ref.Ext[extEtag]
	if s3KeyFlag == "" {
		return driver.DirectLink{}, driver.NewErr(driver.KindNotFound, "缺少 123 文件上下文（S3KeyFlag）,请重新解析", nil)
	}
	body := map[string]any{
		"ShareKey":  key,
		"FileID":    jsonNumber(ref.FID),
		"S3KeyFlag": s3KeyFlag,
		"Size":      jsonNumber(refSize(ref)),
		"Etag":      etag,
	}
	// 签名 path 与请求头一致（含 /b）；分享下载走 android 平台头，签名内部仍固定 web/3（桌面端 §6.3 实证）
	var resp downloadInfoResp
	if _, err := d.postJSON(ctx, d.apiURL(shareDownloadBase, "/b/api/share/download/info"), "/b/api/share/download/info", body, cred.Cookie,
		platformAndroid, appVersionAndroid, &resp); err != nil {
		return driver.DirectLink{}, err
	}
	if err := checkCode(resp.Code, resp.Message, "123 下载信息"); err != nil {
		return driver.DirectLink{}, err
	}
	raw := resp.Data.DownloadURL
	if raw == "" {
		return driver.DirectLink{}, driver.NewErr(driver.KindInterfaceChanged, "123 未返回下载地址", nil)
	}
	real := decodeDownloadURL(raw)
	if real == "" {
		real = raw
	}
	// auto_redirect=0 时 CDN 返回 JSON {data:{redirect_url}}，循环跟随到最终可下载地址
	final, err := d.followRedirects(ctx, real)
	if err != nil {
		return driver.DirectLink{}, err
	}
	return driver.DirectLink{
		URL:       final,
		Referer:   downloadReferer,
		ExpiresAt: time.Now().Add(downloadLinkTTL),
	}, nil
}

func refSize(ref driver.FileRef) string {
	// Size 上游要数字形态；Ext 里带解析时的 Size 兜底，直链请求差 1 字节都会 4xx。
	if s, ok := ref.Ext["size"]; ok && s != "" {
		return s
	}
	return "0"
}

// jsonNumber 把字符串 fid/size 包成 JSON 数字（123 两种形态都收,但抓包实为数字）。
func jsonNumber(s string) json.Number { return json.Number(s) }

// decodeDownloadURL 解码 download-v2 包装（桌面端同款,文档 §5.3.1）：
//   - 形态 1：整段 base64（不含协议头的串）
//   - 形态 2：download-v2?params=<base64 URL-safe> → 解码 params
func decodeDownloadURL(downloadURL string) string {
	t := strings.TrimSpace(downloadURL)
	if !strings.Contains(t, "://") {
		if dec, err := base64Decode(t); err == nil && strings.HasPrefix(dec, "http") {
			return dec
		}
		return ""
	}
	idx := strings.Index(t, "params=")
	if idx < 0 {
		return ""
	}
	params := t[idx+len("params="):]
	if amp := strings.Index(params, "&"); amp >= 0 {
		params = params[:amp]
	}
	dec, err := base64Decode(params)
	if err != nil {
		return ""
	}
	return dec
}

func base64Decode(s string) (string, error) {
	// 形态 2 的 params 是 URL-safe base64（-_），形态 1 是标准 base64（+/）
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return string(b), nil
	}
	b, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ---- CDN redirect_url 跟随 ----

type redirectResp struct {
	Code int `json:"code"`
	Data struct {
		RedirectURL string `json:"redirect_url"`
	} `json:"data"`
}

// followRedirects 与桌面端 followRedirectUrl 同口径：响应体是小 JSON 且含
// data.redirect_url 时跟随，大响应视为真实文件流返回当前 URL。
func (d *Driver) followRedirects(ctx context.Context, initial string) (string, error) {
	u := initial
	for i := 0; i < maxRedirectFollows; i++ {
		next, err := d.probeRedirect(ctx, u)
		if err != nil {
			return "", err
		}
		if next == "" {
			return u, nil
		}
		u = next
	}
	return u, nil
}

func (d *Driver) probeRedirect(ctx context.Context, raw string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", raw, nil)
	if err != nil {
		return "", driver.NewErr(driver.KindUpstream, "构造 123 直链探测失败", err)
	}
	req.Header.Set("Referer", downloadReferer)
	req.Header.Set("User-Agent", dartUA)
	res, err := d.client.Do(req)
	if err != nil {
		return "", driver.NewErr(driver.KindUpstream, "123 直链探测失败", err)
	}
	if res.StatusCode >= 400 {
		return "", driver.NewErr(driver.KindUpstream, fmt.Sprintf("123 直链响应异常:%d", res.StatusCode), nil)
	}
	// 只有响应体很小（≤8KB，JSON 跳转页）才解析：大响应是文件流,绝不能读进内存。
	if cl := res.Header.Get("Content-Length"); cl != "" {
		if n, err := strconv.ParseInt(cl, 10, 64); err == nil && (n < 0 || n > 8192) {
			return "", nil
		}
	}
	if len(res.Body) == 0 || len(res.Body) > 8192 {
		return "", nil
	}
	body := res.Body
	if !strings.HasPrefix(strings.TrimSpace(string(body)), "{") {
		return "", nil
	}
	var rr redirectResp
	if json.Unmarshal(body, &rr) != nil || rr.Data.RedirectURL == "" {
		return "", nil
	}
	return rr.Data.RedirectURL, nil
}

// ---- 凭据 ----

// CheckCredential 校验登录态：GET /b/api/user/info（需签名）。
func (d *Driver) CheckCredential(ctx context.Context, cred driver.Credential) (driver.CredStatus, error) {
	if cred.Cookie == "" {
		return driver.CredStatus{Valid: false, Message: "缺少 123 登录 JWT"}, nil
	}
	var resp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Nickname string `json:"Nickname"`
		} `json:"data"`
	}
	if _, err := d.getJSONAuth(ctx, d.apiURL(shareGetBase, "/b/api/user/info"), "/b/api/user/info", cred.Cookie, &resp); err != nil {
		if de, ok := err.(*driver.Error); ok && de.Kind == driver.KindAuthExpired {
			return driver.CredStatus{Valid: false, Message: "123 登录已失效,请重新登录"}, nil
		}
		return driver.CredStatus{}, err
	}
	if err := checkCode(resp.Code, resp.Message, "123 用户信息"); err != nil {
		return driver.CredStatus{}, err
	}
	return driver.CredStatus{Valid: true, Nickname: resp.Data.Nickname, Message: "登录态有效"}, nil
}

// checkCode 统一成功判定 code==0（登录接口的 200 不在本 driver 范围）。
func checkCode(code int, msg, what string) error {
	if code == 0 {
		return nil
	}
	m := msg
	if m == "" {
		m = what + "失败"
	}
	// 401/登录态类错误码（桌面端实证:401「token 无效或已过期」）按凭据失效分类,
	// 触发账号看门狗而非接口告警。
	if code == 401 || strings.Contains(m, "登录") || strings.Contains(m, "token") || strings.Contains(m, "Token") {
		return driver.NewErr(driver.KindAuthExpired, "123 登录态失效("+m+")", nil)
	}
	// 分享不存在/失效类业务码（生产实证:假 key 恒回 5103「此分享不存在」,参数合法时
	// 稳定复现、无风控）→ KindShareGone:客户端拿到确定性终态,不计入熔断。
	// 400「ShareKey长度异常」「请输入Next」等是链接解析阶段就该拦下的确定性请求错误,
	// 归 KindNotFound 而非上游故障——否则一次手滑链接就会把整条 pan 通道打入熔断。
	if code == 5103 || strings.Contains(m, "分享不存在") || strings.Contains(m, "分享已失效") ||
		strings.Contains(m, "分享已取消") {
		return driver.NewErr(driver.KindShareGone, "123 云盘分享已失效("+m+")", nil)
	}
	if code == 400 && (strings.Contains(m, "长度异常") || strings.Contains(m, "请输入")) {
		return driver.NewErr(driver.KindNotFound, "123 分享链接无效("+m+")", nil)
	}
	return driver.NewErr(driver.KindUpstream, what+"失败("+m+")", nil)
}
