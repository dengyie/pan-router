// Package c139 实现移动云盘(139/和彩云)driver。
// 接口口径对齐桌面端 MangoRouter C139Api.kt(抓包实证,含 hcy-cool-flag 修复与
// 9530 排障记录):
//   - 分享解析(匿名): getOutLinkInfoV6,body AES-CBC 加密(固定 key + 随机 IV 前置),
//     必须 hcy-cool-flag:1(139 网关解密开关,缺它业务层拿不到明文 → 9530);
//     响应加密 base64 解密(兼容明文透传;解密后 gzip 魔数 0x1f8b 先解压)。
//     列表 = caLst(子文件夹) + coLst(文件,coType==2 亦为文件夹)。
//   - 直链(登录态): dlFromOutLinkV3 → data.redrUrl(OBS S3 签名直链,900s 有效);
//     需 Cookie 内 authorization=<Basic base64(pc:账号:authToken)> 与账号字段。
//   - 凭据校验: user-njs.yun.139.com/user/disk/quota/detail(mcloud-sign 签名头 + 渠道头组)。
//   - mcloud-sign 算法: md5(md5(b64(sorted(urlencode(body))))+md5("ts:rand")) 大写,
//     头值 "<ts>,<rand>,<sign>",ts=本地 "yyyy-MM-dd HH:mm:ss",rand=16 位字母数字。
// 链接形态: yun.139.com/shareweb/.../w/i/<linkID>。
package c139

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/dengyie/panrouter/internal/driver"
	"github.com/dengyie/panrouter/internal/pkg/httpx"
)

const (
	shareBase = "https://share-kd-njs.yun.139.com"
	// shareAESKey 分享接口 AES-CBC 固定密钥(桌面端 C139Constants.SHARE_AES_KEY 同源)。
	shareAESKey = "PVGDwmcvfs1uV3d1"

	shareListURL    = "/yun-share/richlifeApp/devapp/IOutLink/getOutLinkInfoV6"
	shareLinkURL    = "/yun-share/richlifeApp/devapp/IOutLink/dlFromOutLinkV3"
	quotaURL        = "https://user-njs.yun.139.com/user/disk/quota/detail"
	origin          = "https://yun.139.com"
	referer         = "https://yun.139.com/"
	shareUA         = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Mobile Safari/537.36"
	pcUA            = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	shareDeviceInfo = "||3|12.27.0|||||chrome 150.0.0.0|360X444|zh-cn|||"
	huaweiSrc       = "10245500"
	mmSource        = "0002"

	// 目录遍历上界:与 quark/pan123/uc 同口径。
	maxShareDepth = 8
	maxShareFiles = 200
	maxShareDirs  = 64
	// obsLinkTTL 是 redrUrl 的实测有效期(900s);留一半余量。
	obsLinkTTL = 7 * time.Minute
)

// 与桌面端 c139ShareIdRegex 同口径:.*? 非贪婪跨过 hash 路由段(#/w/i/)。
var linkIDRe = regexp.MustCompile(`yun\.139\.com/shareweb/.*?/w/i/([A-Za-z0-9_-]+)`)

type Driver struct {
	client *httpx.Client
	base   string // 分享 API 基址;测试注入 httptest 地址
	quota  string // 配额端点;同上
}

func New(client *httpx.Client, base string) *Driver {
	if base == "" {
		base = shareBase
	}
	return &Driver{client: client, base: base, quota: quotaURL}
}

func (d *Driver) ID() string { return "c139" }

// ---- 错误分类 ----
// resultCode 语义(桌面端 + 生产实证):分享失效类文案确定性终态;错误映射不计熔断的
// 口径与 pan123 v2.17.1/uc v2.18.1 统一。

func (d *Driver) classify(resultCode, msg string) *driver.Error {
	m := msg
	switch {
	case strings.Contains(m, "分享不存在") || strings.Contains(m, "链接不存在") ||
		strings.Contains(m, "分享已失效") || strings.Contains(m, "已取消") ||
		strings.Contains(m, "已删除") || resultCode == "10003" || resultCode == "10004":
		return driver.NewErr(driver.KindShareGone, "139 分享已失效("+m+")", nil)
	case strings.Contains(m, "提取码") || strings.Contains(m, "密码"):
		return driver.NewErr(driver.KindNotFound, "139 提取码错误("+m+")", nil)
	case strings.Contains(m, "登录") || strings.Contains(m, "认证") || resultCode == "04000005":
		return driver.NewErr(driver.KindAuthExpired, "139 登录态失效("+m+")", nil)
	case strings.Contains(m, "验证") || strings.Contains(m, "频繁") || strings.Contains(m, "稍后再试"):
		return driver.NewErr(driver.KindRiskControl, "139 触发风控:"+m, nil)
	default:
		return driver.NewErr(driver.KindUpstream, "139 接口异常("+m+")", nil)
	}
}

// ---- AES-CBC 加解密(固定 key,IV 前置;解密后 gzip 魔数先解压) ----

func encryptBody(plaintext string) (string, error) {
	block, err := aes.NewCipher([]byte(shareAESKey))
	if err != nil {
		return "", err
	}
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	pad := 16 - len(plaintext)%16
	padded := make([]byte, 0, len(plaintext)+pad)
	padded = append(padded, plaintext...)
	padded = append(padded, bytes.Repeat([]byte{byte(pad)}, pad)...)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	out := append(append([]byte{}, iv...), ct...)
	return base64.StdEncoding.EncodeToString(out), nil
}

func decryptBody(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) < 16 {
		return "", fmt.Errorf("invalid encrypted body")
	}
	iv, ct := raw[:16], raw[16:]
	block, err := aes.NewCipher([]byte(shareAESKey))
	if err != nil {
		return "", err
	}
	if len(ct)%16 != 0 || len(ct) == 0 {
		return "", fmt.Errorf("ciphertext not multiple of block")
	}
	// 明文透传兜底由调用方处理:这里只解密形态
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ct)
	pad := int(plain[len(plain)-1])
	if pad < 1 || pad > 16 {
		return "", fmt.Errorf("bad padding")
	}
	plain = plain[:len(plain)-pad]
	// gzip 魔数(桌面端/alist YunCrypto 同款)
	if len(plain) > 2 && plain[0] == 0x1f && plain[1] == 0x8b {
		gz, err := gzip.NewReader(bytes.NewReader(plain))
		if err != nil {
			return "", err
		}
		var out bytes.Buffer
		if _, err := out.ReadFrom(gz); err != nil {
			return "", err
		}
		plain = out.Bytes()
	}
	return string(plain), nil
}

// ---- mcloud-sign ----

// encodeURIComponent 与桌面端同口径(:/. 等保留字符除外)。
func encodeURIComponent(s string) string {
	s = url.QueryEscape(s)
	s = strings.ReplaceAll(s, "+", "%20")
	return s
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// calSign 对齐桌面端:md5(md5(b64(sorted(urlencode(body)))) + md5("ts:rand")) 大写。
func calSign(bodyJSON, ts, randStr string) string {
	encoded := encodeURIComponent(bodyJSON)
	chars := []rune(encoded)
	for i := 1; i < len(chars); i++ { // rune 排序(与 Kotlin sorted() 同语义)
		for j := i; j > 0 && chars[j] < chars[j-1]; j-- {
			chars[j], chars[j-1] = chars[j-1], chars[j]
		}
	}
	b64 := base64.StdEncoding.EncodeToString([]byte(string(chars)))
	res := md5hex(b64) + md5hex(ts+":"+randStr)
	return strings.ToUpper(md5hex(res))
}

// signHeader 生成 mcloud-sign 头值 "<ts>,<rand>,<sign>"。
func signHeader(bodyJSON string) string {
	ts := time.Now().Format("2006-01-02 15:04:05")
	const pool = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	rb := make([]byte, 16)
	_, _ = rand.Read(rb)
	randStr := make([]rune, 16)
	for i, b := range rb {
		randStr[i] = rune(pool[int(b)%len(pool)])
	}
	return ts + "," + string(randStr) + "," + calSign(bodyJSON, ts, string(randStr))
}

// ---- 分享请求(匿名/加密) ----

// shareHeaders 分享通道公共头(hcy-cool-flag:1 为网关解密开关,缺它 → 9530)。
func shareHeaders() map[string]string {
	return map[string]string{
		"hcy-cool-flag":        "1",
		"x-deviceinfo":         shareDeviceInfo,
		"x-huawei-channelsrc":  huaweiSrc,
		"x-mm-source":          mmSource,
		"Content-Type":         "application/json;charset=UTF-8",
		"User-Agent":           shareUA,
		"Origin":               origin,
		"Referer":              referer,
		"Accept":               "application/json, text/plain, */*",
	}
}

// sharePost 匿名分享 POST:加密 body → 解密响应(明文透传兜底)。
func (d *Driver) sharePost(ctx context.Context, rawURL, plainBody string) (json.RawMessage, error) {
	enc, err := encryptBody(plainBody)
	if err != nil {
		return nil, driver.NewErr(driver.KindUpstream, "139 请求加密失败", err)
	}
	h := shareHeaders()
	res, err := d.postRaw(ctx, rawURL, h, enc)
	if err != nil {
		return nil, err
	}
	body := strings.TrimSpace(string(res.Body))
	// 响应应为加密 base64;JSON 开头(明文透传)直接用
	var plain string
	if strings.HasPrefix(body, "{") {
		plain = body
	} else {
		plain, err = decryptBody(body)
		if err != nil {
			return nil, driver.NewErr(driver.KindInterfaceChanged, "139 响应解密失败,疑似接口改版", err)
		}
	}
	return json.RawMessage(plain), nil
}

// postRaw 发送原始字符串 body(加密体不能经 DoJSON 二次 marshal)。
func (d *Driver) postRaw(ctx context.Context, rawURL string, h map[string]string, body string) (*httpx.Result, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", rawURL, strings.NewReader(body))
	if err != nil {
		return nil, driver.NewErr(driver.KindUpstream, "139 请求构造失败", err)
	}
	for k, v := range h {
		req.Header.Set(k, v)
	}
	res, err := d.client.Do(req)
	if err != nil {
		return nil, driver.NewErr(driver.KindUpstream, "139 网络请求失败", err)
	}
	return res, nil
}

// shareResp 解析公共外壳 resultCode/success/desc。
func (d *Driver) shareResp(raw json.RawMessage, what string) (*shareEnvelope, error) {
	var env shareEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, driver.NewErr(driver.KindInterfaceChanged, what+"响应不是合法 JSON,疑似接口改版", err)
	}
	if env.ResultCode != "" && env.ResultCode != "0" {
		msg := env.Desc
		if msg == "" {
			msg = env.Message
		}
		if msg == "" {
			msg = "resultCode=" + env.ResultCode
		}
		return nil, d.classify(env.ResultCode, msg)
	}
	if env.Success != nil && !*env.Success {
		msg := env.Desc
		if msg == "" {
			msg = env.Message
		}
		if msg == "" {
			msg = what + "失败"
		}
		return nil, d.classify(env.ResultCode, msg)
	}
	return &env, nil
}

type shareEnvelope struct {
	ResultCode string  `json:"resultCode"`
	Success    *bool   `json:"success"`
	Desc       string  `json:"desc"`
	Message    string  `json:"message"`
	Data       RawData `json:"data"`
}

// RawData 透传原始 data 供二次解析。
type RawData = json.RawMessage

// ---- 分享列表 ----

type c139Item struct {
	FID    string `json:"caID"` // 目录项
	CoID   string `json:"coID"` // 文件项
	Name   string `json:"caName"`
	CoName string `json:"coName"`
	Size   int64  `json:"coSize"`
	Dir    *bool  `json:"isdir"`
	CoType int    `json:"coType"`
}

func (i *c139Item) isDir() bool {
	if i.Dir != nil {
		return *i.Dir
	}
	return i.CoType == 2
}

func (i *c139Item) id() string {
	if i.FID != "" {
		return i.FID
	}
	return i.CoID
}

func (i *c139Item) name() string {
	if i.Name != "" {
		return i.Name
	}
	return i.CoName
}

// getShareFiles 列出分享内某目录(bNum/eNum 窗口分页,一次取 200 与预算上界对齐)。
func (d *Driver) getShareFiles(ctx context.Context, linkID, pcaID, passwd string) ([]c139Item, error) {
	req := map[string]any{
		"account": "", // 列表端点 account 必须为空串,且不带鉴权头(桌面端 §3 实证)
		"linkID":  linkID,
		"passwd":  passwd,
		"caSrt":   1,
		"coSrt":   1,
		"srtDr":   0,
		"bNum":    1,
		"pCaID":   pcaID,
		"eNum":    200,
	}
	plain, _ := json.Marshal(map[string]any{"getOutLinkInfoReq": req})
	raw, err := d.sharePost(ctx, d.base+shareListURL, string(plain))
	if err != nil {
		return nil, err
	}
	env, err := d.shareResp(raw, "139 文件列表")
	if err != nil {
		return nil, err
	}
	var data struct {
		CaLst []c139Item `json:"caLst"`
		CoLst []c139Item `json:"coLst"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		return nil, driver.NewErr(driver.KindInterfaceChanged, "139 文件列表响应结构变化,解析失败", err)
	}
	return append(data.CaLst, data.CoLst...), nil
}

// walkShare 递归展开分享目录,只返回文件(名称带相对路径)。
func (d *Driver) walkShare(ctx context.Context, linkID, passwd, pcaID, prefix string, depth int, seen map[string]struct{}, bud *shareWalkBudget) ([]driver.FileNode, error) {
	if err := ctx.Err(); err != nil {
		return nil, driver.NewErr(driver.KindUpstream, "分享目录遍历已取消", err)
	}
	if depth > maxShareDepth || bud.files <= 0 {
		bud.truncated = true
		return nil, nil
	}
	entries, err := d.getShareFiles(ctx, linkID, pcaID, passwd)
	if err != nil {
		return nil, err
	}
	var nodes []driver.FileNode
	var dirs []c139Item
	for _, f := range entries {
		id := f.id()
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		if f.isDir() {
			dirs = append(dirs, f)
			continue
		}
		if bud.files <= 0 {
			bud.truncated = true
			break
		}
		bud.files--
		nodes = append(nodes, driver.FileNode{
			FID:   id,
			Name:  joinSharePath(prefix, f.name()),
			Size:  f.Size,
			IsDir: false,
			// 提链上下文:linkID/passwd;coIDLst 取直链时必需
			Ext: map[string]string{"link_id": linkID, "passwd": passwd},
		})
	}
	for _, dir := range dirs {
		if bud.dirs <= 0 || bud.files <= 0 || depth >= maxShareDepth {
			bud.truncated = true
			break
		}
		bud.dirs--
		kids, err := d.walkShare(ctx, linkID, passwd, dir.id(), joinSharePath(prefix, dir.name()), depth+1, seen, bud)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, kids...)
	}
	return nodes, nil
}

type shareWalkBudget struct {
	files     int
	dirs      int
	truncated bool
}

func joinSharePath(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "/" + name
}

// ResolveShare 解析 139 分享链接(匿名,免登录)。
func (d *Driver) ResolveShare(ctx context.Context, share driver.ShareLink, cred *driver.Credential) ([]driver.FileNode, error) {
	m := linkIDRe.FindStringSubmatch(share.URL)
	if m == nil {
		return nil, driver.NewErr(driver.KindNotFound, "无法识别的 139 分享链接", nil)
	}
	linkID := m[1]
	bud := &shareWalkBudget{files: maxShareFiles, dirs: maxShareDirs}
	nodes, err := d.walkShare(ctx, linkID, share.Pwd, "0", "", 0, map[string]struct{}{}, bud)
	if err != nil {
		return nil, err
	}
	if bud.truncated {
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

// ---- 直链(登录态) ----

// credentialParts 从登录 Cookie 提取 authorization 与账号(桌面端 extractAuthorization/
// extractAccountFull 同口径:ORCHES-I-ACCOUNT-ENCRYPT → authorization → Login_UserNumber)。
func credentialParts(cookie string) (auth string, account string, err error) {
	if cookie == "" {
		return "", "", driver.NewErr(driver.KindAuthExpired, "139 分享直链需要登录态,请先在「账号管理」添加 139 账号 Cookie", nil)
	}
	for _, kv := range strings.Split(cookie, ";") {
		kv = strings.TrimSpace(kv)
		switch {
		case strings.HasPrefix(kv, "authorization="):
			auth = kv[len("authorization="):]
		case strings.HasPrefix(kv, "ORCHES-I-ACCOUNT-ENCRYPT="):
			if dec, derr := base64.StdEncoding.DecodeString(kv[len("ORCHES-I-ACCOUNT-ENCRYPT="):]); derr == nil && len(dec) > 0 {
				account = string(dec)
			}
		case strings.HasPrefix(kv, "Login_UserNumber=") && account == "":
			account = kv[len("Login_UserNumber="):]
		}
	}
	// authorization 解码兜底账号(base64("pc:<账号>:<authToken>") 第 2 段)
	if account == "" && strings.HasPrefix(auth, "Basic") {
		if dec, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(auth, "Basic"))); derr == nil {
			if parts := strings.SplitN(string(dec), ":", 3); len(parts) >= 2 {
				account = parts[1]
			}
		}
	}
	if auth == "" || account == "" {
		return "", "", driver.NewErr(driver.KindAuthExpired, "139 Cookie 缺少 authorization/账号信息,请重新登录", nil)
	}
	return auth, account, nil
}

// GetDirectLink 分享直链(登录态):dlFromOutLinkV3 → data.redrUrl。
func (d *Driver) GetDirectLink(ctx context.Context, cred *driver.Credential, ref driver.FileRef) (driver.DirectLink, error) {
	if ref.Own {
		return driver.DirectLink{}, driver.NewErr(driver.KindUnsupported, "139 个人云盘内文件提链暂不支持,仅支持分享解析", nil)
	}
	linkID := ref.Ext["link_id"]
	if linkID == "" {
		return driver.DirectLink{}, driver.NewErr(driver.KindNotFound, "缺少 139 分享上下文,请重新解析", nil)
	}
	auth, account, err := credentialParts(credCookie(cred))
	if err != nil {
		return driver.DirectLink{}, err
	}
	req := map[string]any{
		"account":         account,
		"linkID":          linkID,
		"coIDLst":         map[string]any{"item": []string{ref.FID}},
		"commonAccountInfo": map[string]any{"account": account, "accountType": 1},
	}
	plain, _ := json.Marshal(map[string]any{"dlFromOutLinkReqV3": req})
	enc, err := encryptBody(string(plain))
	if err != nil {
		return driver.DirectLink{}, driver.NewErr(driver.KindUpstream, "139 请求加密失败", err)
	}
	h := shareHeaders()
	h["mcloud-sign"] = signHeader(string(plain))
	if auth != "" {
		h["Authorization"] = auth
	}
	res, err := d.postRaw(ctx, d.base+shareLinkURL, h, enc)
	if err != nil {
		return driver.DirectLink{}, err
	}
	body := strings.TrimSpace(string(res.Body))
	var raw json.RawMessage
	if strings.HasPrefix(body, "{") {
		raw = json.RawMessage(body)
	} else if plain, derr := decryptBody(body); derr == nil {
		raw = json.RawMessage(plain)
	} else {
		return driver.DirectLink{}, driver.NewErr(driver.KindInterfaceChanged, "139 响应解密失败,疑似接口改版", derr)
	}
	env, err := d.shareResp(raw, "139 下载链接")
	if err != nil {
		return driver.DirectLink{}, err
	}
	var data struct {
		RedrURL string `json:"redrUrl"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil || data.RedrURL == "" {
		return driver.DirectLink{}, driver.NewErr(driver.KindInterfaceChanged, "139 响应缺少 redrUrl,疑似接口改版", err)
	}
	return driver.DirectLink{
		URL:       data.RedrURL,
		UA:        pcUA,
		Referer:   referer,
		Cookie:    "", // OBS S3 签名直链不绑 Cookie(浏览器 302 可用)
		BindIP:    false,
		ExpiresAt: time.Now().Add(obsLinkTTL),
	}, nil
}

func credCookie(cred *driver.Credential) string {
	if cred == nil {
		return ""
	}
	return cred.Cookie
}

// ---- 凭据校验 ----

// CheckCredential 走配额端点(需要 authorization+账号+mcloud-sign+渠道头组)。
func (d *Driver) CheckCredential(ctx context.Context, cred driver.Credential) (driver.CredStatus, error) {
	if cred.Cookie == "" {
		return driver.CredStatus{Valid: false, Message: "Cookie 为空"}, nil
	}
	auth, account, err := credentialParts(cred.Cookie)
	if err != nil {
		return driver.CredStatus{Valid: false, Message: "Cookie 缺少 authorization/账号信息"}, nil
	}
	req := map[string]any{
		"userDomainId":      "",
		"commonAccountInfo": map[string]any{"account": account, "accountType": 1},
	}
	plain, _ := json.Marshal(req)
	h := map[string]string{
		"Authorization":         auth,
		"mcloud-sign":           signHeader(string(plain)),
		"mcloud-skey":           cookieValue(cred.Cookie, "skey"),
		"x-yun-channel-source":  "10000034",
		"x-yun-app-channel":     "10000034",
		"x-huawei-channelSrc":   "10000034",
		"mcloud-version":        "7.17.9",
		"mcloud-client":         "10701",
		"mcloud-channel":        "1000101",
		"mcloud-route":          "001",
		"x-yun-module-type":     "100",
		"x-yun-api-version":     "v1",
		"x-yun-svc-type":        "1",
		"x-SvcType":             "1",
		"caller":                "web",
		"x-inner-ntwk":          "2",
		"CMS-DEVICE":            "default",
		"x-m4c-src":             "10002",
		"x-m4c-caller":          "PC",
		"X-Deviceinfo":          "||9|7.17.9|chrome|116.0.0.0|2cdaf7ada9e353c70eba99092e177991||windows 10||zh-CN|||",
		"Content-Type":          "application/json;charset=UTF-8",
		"User-Agent":            pcUA,
		"Origin":                origin,
		"Referer":               referer,
		"Accept":                "application/json, text/plain, */*",
	}
	res, err := d.postRaw(ctx, d.quota, h, string(plain))
	if err != nil {
		return driver.CredStatus{}, driver.NewErr(driver.KindUpstream, "139 网络请求失败", err)
	}
	var resp struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(res.Body, &resp); err != nil {
		return driver.CredStatus{}, driver.NewErr(driver.KindInterfaceChanged, "139 配额响应不是合法 JSON,疑似接口改版", err)
	}
	if resp.Success && (resp.Code == "0000" || resp.Code == "0") {
		return driver.CredStatus{Valid: true, Nickname: account, Message: "登录态有效"}, nil
	}
	msg := resp.Message
	if msg == "" {
		msg = "code=" + resp.Code
	}
	return driver.CredStatus{Valid: false, Message: msg}, nil
}

// cookieValue 从 Cookie 串取指定项值(无则空串)。
func cookieValue(cookie, name string) string {
	for _, kv := range strings.Split(cookie, ";") {
		kv = strings.TrimSpace(kv)
		if strings.HasPrefix(kv, name+"=") {
			return kv[len(name)+1:]
		}
	}
	return ""
}
