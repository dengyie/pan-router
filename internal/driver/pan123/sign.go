// 123 云盘签名算法（auth-key / auth-value）与鉴权请求封装。
// 口径对齐桌面端 MangoRouter Pan123Api.makeSign（文档 §6 抓包逐字还原 + 实时验证）：
//   - auth-key = crc32_hex(替换表映射后的 UTC "YYYYMMDDHHmm"，时间基准 = ts + 57600s)；
//   - auth-value = "<ts>-<random>-<crc32_hex(ts|random|path|web|3|auth-key)>"；
//   - 签名内部固定 OS=web / VER=3，与请求头 platform/app-version 无关（§6.3）。
package pan123

import (
	"context"
	"hash/crc32"
	"strconv"
	"time"

	"github.com/dengyie/panrouter/internal/driver"
	"github.com/dengyie/panrouter/internal/pkg/httpx"
)

const (
	platformWeb     = "web"
	platformAndroid = "android"
	appVersionWeb   = "3"
	appVersionAndroid = "39"
	signOffset      = 57600 // +16h（抓包实证）
)

// signTable 数字 0-9 的替换表（索引 = 数字值，§6.2）。
const signTable = "adefghlmyijnopkqrstubcvwsz"

// makeSign 生成 (auth-key, auth-value)。path 含 /b 前缀、不含 host、不含 query。
func makeSign(path string, ts int64) (string, string) {
	if ts == 0 {
		ts = time.Now().Unix()
	}
	// 1) auth-key：ts+16h 按 UTC 格式化 YYYYMMDDHHmm 后逐数字替换再 crc32
	t := time.Unix(ts+signOffset, 0).UTC()
	minute := t.Format("200601021504")
	sub := make([]byte, len(minute))
	for i := 0; i < len(minute); i++ {
		sub[i] = signTable[minute[i]-'0']
	}
	authKey := strconv.FormatUint(uint64(crc32.ChecksumIEEE(sub)), 16)

	// 2) auth-value：ts|random|path|web|3|auth-key 的 crc32
	random := strconv.Itoa(int(time.Now().UnixNano()%10_000_000))
	data := strconv.FormatInt(ts, 10) + "|" + random + "|" + path + "|" + "web" + "|3|" + authKey
	authValue := strconv.FormatInt(ts, 10) + "-" + random + "-" + strconv.FormatUint(uint64(crc32.ChecksumIEEE([]byte(data))), 16)
	return authKey, authValue
}

// authHeaders 组装带签名头的公共请求头。
func authHeaders(path, token, platform, appVersion string) map[string]string {
	ak, av := makeSign(path, 0)
	return map[string]string{
		"platform":     platform,
		"app-version":  appVersion,
		"authorization": "Bearer " + token,
		"loginuuid":    "panrouter-server",
		"auth-key":     ak,
		"auth-value":   av,
		"User-Agent":   webUA,
		"Accept":       "application/json, text/plain, */*",
	}
}

func (d *Driver) getJSON(ctx context.Context, rawURL string, headers map[string]string, out any) (*httpx.Result, error) {
	res, err := d.client.DoJSON(ctx, "GET", rawURL, headers, nil, out)
	if err != nil {
		return res, driver.NewErr(driver.KindUpstream, "123 网络请求失败", err)
	}
	return res, nil
}

// getJSONAuth 匿名分享列表用不到签名，但 user/info 等鉴权 GET 需要。
func (d *Driver) getJSONAuth(ctx context.Context, rawURL, path, token string, out any) (*httpx.Result, error) {
	return d.getJSON(ctx, rawURL, authHeaders(path, token, platformWeb, appVersionWeb), out)
}

func (d *Driver) postJSON(ctx context.Context, rawURL, signPath string, body any, token, platform, appVersion string, out any) (*httpx.Result, error) {
	h := authHeaders(signPath, token, platform, appVersion)
	h["Content-Type"] = "application/json;charset=UTF-8"
	res, err := d.client.DoJSON(ctx, "POST", rawURL, h, body, out)
	if err != nil {
		return res, driver.NewErr(driver.KindUpstream, "123 网络请求失败", err)
	}
	return res, nil
}

// badBodySnippet 截断的响应片段（抹掉可能的凭据字段后供排障）。
func badBodySnippet(res *httpx.Result, decodeErr error) error {
	body := string(res.Body)
	if len(body) > 512 {
		body = body[:512]
	}
	if len(body) > 0 && body[0] == '<' {
		return driver.NewErr(driver.KindRiskControl, "123 返回验证/风控页(HTTP "+strconv.Itoa(res.StatusCode)+"),请稍后重试或换账号", decodeErr)
	}
	return driver.NewErr(driver.KindInterfaceChanged, "123 响应不是有效 JSON(HTTP "+strconv.Itoa(res.StatusCode)+")", decodeErr)
}
