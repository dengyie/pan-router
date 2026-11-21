// Package uc 实现 UC 网盘 driver。
// 接口口径对齐桌面端 MangoRouter UCApi.kt（抓包实证,与夸克同源结构:仅域名/pr/UA 不同）:
//   - 分享解析: share/sharepage/token 取 stoken → sharepage/v2/detail(POST JSON)遍历目录;
//   - 直链: file/download?entry=ft(分享通道)——**游客可用**,响应 Set-Cookie 下发游客态
//     `__pugs`(3h 有效,与本次直链同响应绑定,缺它 CDN 403 RequestDeniedByCallback);
//   - 凭据校验: drive.uc.cn/account/info(success:true + data.nickname)。
// 链接形态: drive.uc.cn/s/<pwdID>。
package uc

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/dengyie/panrouter/internal/driver"
	"github.com/dengyie/panrouter/internal/pkg/httpx"
)

const (
	apiBase       = "https://pc-api.uc.cn"
	infoURL       = "https://drive.uc.cn/account/info"
	origin        = "https://drive.uc.cn"
	referer       = "https://drive.uc.cn/"
	userAgent     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	// 游客链路专用 UA:uc-cloud-drive Electron 客户端,游客取链与下字节都用它(风控比登录态严)。
	guestUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) uc-cloud-drive/2.5.20 Chrome/100.0.4896.160 Electron/18.3.5.4-b478491100 Safari/537.36 Channel/pckk_other_ch"
	// secChUA 与 guestUA 配套的 Sec-Ch-Ua 头(游客链路同款)。
	secChUA = `"Not=A?Brand";v="99", "Chromium";v="100", "Google Chrome";v="100"`
	linkTTL = 2 * time.Hour
	// 目录遍历上界:与 quark/pan123 同口径,防异常响应或超大分享拖死解析。
	maxShareDepth = 8
	maxShareFiles = 200
	maxShareDirs  = 64
)

var pwdIDRe = regexp.MustCompile(`drive\.uc\.cn/s/([0-9a-zA-Z]+)`)

// prQuery 是 UC 全部 pc-api 端点共用的 query 前缀。
const prQuery = "pr=UCBrowser&fr=pc"

type Driver struct {
	client *httpx.Client
	base   string // pc-api 基址;测试注入 httptest 地址
	info   string // account/info 基址;同上

	// guestPugs 缓存游客态令牌(__pugs,3h 有效):取链响应 Set-Cookie 下发,与直链
	// 同响应绑定;仅游客路径读写,登录态路径完全不受影响。
	pugsMu   sync.Mutex
	guestPugs string
}

func New(client *httpx.Client, base string) *Driver {
	if base == "" {
		base = apiBase
	}
	return &Driver{client: client, base: base, info: infoURL}
}

func (d *Driver) ID() string { return "uc" }

// ---- API 响应结构 ----

// apiResp 对齐桌面端判定:成功为 code==0 且 status==200(部分端点只给其一,故任一非零即失败)。
type apiResp struct {
	Code    int             `json:"code"`
	Status  int             `json:"status"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// ucFile 对齐 v2/detail 的 detail_info.list 字段(share_fid_token 与 stoken 绑定)。
type ucFile struct {
	FID           string `json:"fid"`
	FileName      string `json:"file_name"`
	Size          int64  `json:"size"`
	Dir           bool   `json:"dir"`
	PdirFID       string `json:"pdir_fid"`
	ShareFIDToken string `json:"share_fid_token"`
}

// ---- 错误分类 ----
// 错误码表对齐桌面端 guestErrorMessage(31001/23018/14001/41020 为游客链路实证码)。

func (d *Driver) classify(code int, msg string) *driver.Error {
	switch {
	case code == 31001 || strings.Contains(msg, "登录"):
		return driver.NewErr(driver.KindAuthExpired, "该分享需要登录 UC 网盘后才能下载("+msg+")", nil)
	case code == 23018 || strings.Contains(msg, "游客"):
		return driver.NewErr(driver.KindAuthExpired, "该文件超出游客可获取上限,请添加 UC 账号("+msg+")", nil)
	case code == 14001 || code == 41020 || strings.Contains(msg, "失效") || strings.Contains(msg, "过期"):
		return driver.NewErr(driver.KindShareGone, "UC 分享已失效或令牌过期,请重新解析("+msg+")", nil)
	case strings.Contains(msg, "验证") || strings.Contains(msg, "频繁") || strings.Contains(msg, "稍后再试"):
		return driver.NewErr(driver.KindRiskControl, "UC 触发风控:"+msg, nil)
	default:
		return driver.NewErr(driver.KindUpstream, "UC 接口异常:"+msg, nil)
	}
}

// ---- 内部请求 ----

// call 发送 UC API 请求并解析公共外壳。游客请求(cred 为 nil)带游客 UA 与缓存 __pugs。
func (d *Driver) call(ctx context.Context, method, rawURL string, body any, cred *driver.Credential, out *apiResp) (*httpx.Result, error) {
	h := map[string]string{
		"User-Agent": userAgent,
		"Origin":     origin,
		"Referer":    referer,
	}
	if cred != nil && cred.Cookie != "" {
		h["Cookie"] = cred.Cookie
	}
	res, err := d.client.DoJSON(ctx, method, rawURL, h, body, out)
	if err != nil {
		if errors.Is(err, httpx.ErrBadPayload) {
			return res, driver.NewErr(driver.KindInterfaceChanged, "UC 响应不是合法 JSON,疑似接口改版", err)
		}
		return res, driver.NewErr(driver.KindUpstream, "UC 网络请求失败", err)
	}
	return res, nil
}

// ok 判定成功:code==0 或 status==200(桌面端 getShareDownloadLink 看 status,
// getGuestShareDownloadLink 看 code==0,两种成功标志并存)。
func ok(resp *apiResp) bool {
	return resp.Code == 0 || resp.Status == 200
}

func (d *Driver) stoken(ctx context.Context, pwdID, passcode string, cred *driver.Credential) (string, error) {
	u := d.base + "/1/clouddrive/share/sharepage/token?" + prQuery
	var resp apiResp
	if _, err := d.call(ctx, "POST", u, map[string]any{
		"pwd_id": pwdID, "passcode": passcode, "share_for_transfer": true,
	}, cred, &resp); err != nil {
		return "", err
	}
	if !ok(&resp) {
		return "", d.classify(resp.Code, resp.Message)
	}
	var data struct {
		Stoken string `json:"stoken"`
	}
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		return "", driver.NewErr(driver.KindInterfaceChanged, "UC 响应结构变化,解析失败", err)
	}
	if data.Stoken == "" {
		return "", driver.NewErr(driver.KindInterfaceChanged, "UC 响应缺少 stoken", nil)
	}
	return data.Stoken, nil
}
