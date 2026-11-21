// 直链与凭据:GetDirectLink(游客优先,无需登录态)、__pugs 捕获、CheckCredential。
// 游客取链口径对齐桌面端 getGuestShareDownloadLink:同一 file/download?entry=ft 端点,
// 不带账号 Cookie,只带分享参数 + uc-cloud-drive 客户端 UA;下载层只认一个 Cookie——
// 服务端随本次响应 Set-Cookie 下发的游客态 __pugs(3h 有效,与本次直链同响应绑定,
// 缺它 CDN 直接 403 RequestDeniedByCallback)。
package uc

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/dengyie/panrouter/internal/driver"
	"github.com/dengyie/panrouter/internal/pkg/httpx"
)

func (d *Driver) GetDirectLink(ctx context.Context, cred *driver.Credential, ref driver.FileRef) (driver.DirectLink, error) {
	if ref.Own {
		if cred == nil || cred.Cookie == "" {
			return driver.DirectLink{}, driver.NewErr(driver.KindAuthExpired, "UC 网盘内文件提链需要登录态,请添加 UC 账号 Cookie", nil)
		}
		return d.downloadLink(ctx, cred, map[string]any{"fids": []string{ref.FID}}, true)
	}

	// 分享模式:游客优先——__pugs 游客链路开箱即用,无需账号贡献。
	pwdID := ref.Ext["pwd_id"]
	st := ref.Ext["stoken"]
	fidToken := ref.Ext["fid_token"]
	if pwdID == "" || st == "" {
		return driver.DirectLink{}, driver.NewErr(driver.KindNotFound, "缺少 UC 分享上下文,请重新解析", nil)
	}
	if fidToken == "" {
		return driver.DirectLink{}, driver.NewErr(driver.KindNotFound, "缺少 UC 文件令牌(fid_token),请重新解析", nil)
	}
	body := map[string]any{
		"fids":       []string{ref.FID},
		"pwd_id":     pwdID,
		"stoken":     st,
		"fids_token": []string{fidToken},
	}
	if cred != nil && cred.Cookie != "" {
		// 登录态:登录 Cookie 优先(桌面端 getShareDownloadLink 口径),直链绑登录 Cookie。
		return d.downloadLink(ctx, cred, body, false)
	}
	// 游客态:UA 换 uc-cloud-drive 客户端(游客链路风控更严),捕获响应 __pugs 绑直链。
	return d.guestDownloadLink(ctx, body)
}

// downloadLink 登录态取链(个人云盘与分享共用 file/download?entry=ft 端点;登录 UA)。
func (d *Driver) downloadLink(ctx context.Context, cred *driver.Credential, body any, own bool) (driver.DirectLink, error) {
	u := d.base + "/1/clouddrive/file/download?entry=ft&" + prQuery
	h := map[string]string{
		"User-Agent": userAgent,
		"Origin":     origin,
		"Referer":    referer,
		"Cookie":     cred.Cookie,
	}
	var resp apiResp
	res, err := d.client.DoJSON(ctx, "POST", u, h, body, &resp)
	if err != nil {
		if err == httpx.ErrBadPayload {
			return driver.DirectLink{}, driver.NewErr(driver.KindInterfaceChanged, "UC 响应不是合法 JSON,疑似接口改版", err)
		}
		return driver.DirectLink{}, driver.NewErr(driver.KindUpstream, "UC 网络请求失败", err)
	}
	if resp.Code != 0 && resp.Status != 200 {
		return driver.DirectLink{}, d.classify(resp.Code, resp.Message)
	}
	link, err := d.linkFromList(userAgent, &resp)
	if err != nil {
		return driver.DirectLink{}, err
	}
	// 登录态 Cookie 为基底,响应轮换字段(如 __puus 同族)同名覆盖。
	link.Cookie = mergeCookies(cred.Cookie, joinCookies(res.Header.Values("Set-Cookie")))
	return link, nil
}

// guestDownloadLink 游客取链:guestUA + Sec-Ch-Ua + 缓存 __pugs;响应 __pugs 覆盖缓存并绑直链。
func (d *Driver) guestDownloadLink(ctx context.Context, body any) (driver.DirectLink, error) {
	u := d.base + "/1/clouddrive/file/download?entry=ft&" + prQuery
	h := map[string]string{
		"User-Agent":  guestUA,
		"Sec-Ch-Ua":   secChUA,
		"Origin":      origin,
		"Referer":     referer,
		"Currency":    "guest",
		"Content-Type": "application/json",
	}
	d.pugsMu.Lock()
	pugs := d.guestPugs
	d.pugsMu.Unlock()
	if pugs != "" {
		h["Cookie"] = pugs
	}
	var resp apiResp
	res, err := d.client.DoJSON(ctx, "POST", u, h, body, &resp)
	if err != nil {
		if err == httpx.ErrBadPayload {
			// 非 JSON(风控页/HTML)时按风险分类
			return driver.DirectLink{}, driver.NewErr(driver.KindRiskControl, "UC 游客取链响应异常,疑似风控页", err)
		}
		return driver.DirectLink{}, driver.NewErr(driver.KindUpstream, "UC 网络请求失败", err)
	}
	// 先取本次响应的 __pugs(与本次直链同响应绑定,不能用别的响应/上一次的值)
	responsePugs := pugsFromSetCookies(res.Header.Values("Set-Cookie"))
	if responsePugs != "" {
		d.pugsMu.Lock()
		d.guestPugs = responsePugs
		d.pugsMu.Unlock()
	}
	if resp.Code != 0 && resp.Status != 200 {
		return driver.DirectLink{}, d.classify(resp.Code, resp.Message)
	}
	link, err := d.linkFromList(guestUA, &resp)
	if err != nil {
		return driver.DirectLink{}, err
	}
	// 游客态直链只认 __pugs(缺它 CDN 403);无响应下发时沿用缓存值。
	link.Cookie = responsePugs
	if link.Cookie == "" {
		link.Cookie = pugs
	}
	return link, nil
}

// linkFromList 解析 data[0].download_url(file/download 返回数组形态)。
// ua:游客链路必须用 guestUA(桌面端口径:取链与下字节都用 uc-cloud-drive 客户端);
// 登录链路用 userAgent。
func (d *Driver) linkFromList(ua string, resp *apiResp) (driver.DirectLink, error) {
	var data []struct {
		DownloadURL string `json:"download_url"`
	}
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		return driver.DirectLink{}, driver.NewErr(driver.KindInterfaceChanged, "UC 响应结构变化,解析失败", err)
	}
	if len(data) == 0 || data[0].DownloadURL == "" {
		return driver.DirectLink{}, driver.NewErr(driver.KindInterfaceChanged, "UC 响应缺少下载直链", nil)
	}
	return driver.DirectLink{
		URL:       data[0].DownloadURL,
		UA:        ua,
		Referer:   referer,
		BindIP:    false,
		ExpiresAt: time.Now().Add(linkTTL),
	}, nil
}

// pugsFromSetCookies 从 Set-Cookie 列表提取 __pugs 值(返回 "__pugs=值" 完整对,可直接当 Cookie 头)。
func pugsFromSetCookies(setCookies []string) string {
	for _, sc := range setCookies {
		kv := strings.TrimSpace(strings.SplitN(sc, ";", 2)[0])
		if strings.HasPrefix(kv, "__pugs=") && len(kv) > len("__pugs=") {
			return kv
		}
	}
	return ""
}

// mergeCookies 以 base 为基底,patch 中同名项覆盖(base 顺序在前保证可读性)。
func mergeCookies(base, patch string) string {
	if patch == "" {
		return base
	}
	if base == "" {
		return strings.TrimSpace(patch)
	}
	result := []string{}
	seen := map[string]string{}
	for _, part := range strings.Split(base, ";") {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 || strings.TrimSpace(kv[0]) == "" {
			continue
		}
		seen[strings.TrimSpace(kv[0])] = kv[1]
		result = append(result, part)
	}
	for _, part := range strings.Split(patch, ";") {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 || strings.TrimSpace(kv[0]) == "" {
			continue
		}
		name := strings.TrimSpace(kv[0])
		if _, ok := seen[name]; ok {
			for i, p := range result {
				if strings.TrimSpace(strings.SplitN(p, "=", 2)[0]) == name {
					result[i] = part
					break
				}
			}
		} else {
			result = append(result, part)
		}
		seen[name] = kv[1]
	}
	return strings.Join(result, "; ")
}

// joinCookies 把 Set-Cookie 合并为请求用 Cookie 串(取 name=value 对,去重)。
func joinCookies(setCookies []string) string {
	var parts []string
	seen := map[string]bool{}
	for _, sc := range setCookies {
		kv := strings.TrimSpace(strings.SplitN(sc, ";", 2)[0])
		name := strings.TrimSpace(strings.SplitN(kv, "=", 2)[0])
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		parts = append(parts, kv)
	}
	return strings.Join(parts, "; ")
}

func (d *Driver) CheckCredential(ctx context.Context, cred driver.Credential) (driver.CredStatus, error) {
	if cred.Cookie == "" {
		return driver.CredStatus{Valid: false, Message: "Cookie 为空"}, nil
	}
	// 对齐桌面端 fetchNickname:drive.uc.cn/account/info,成功标志 success:true + data.nickname。
	h := map[string]string{
		"User-Agent": userAgent,
		"Referer":    referer,
		"Cookie":     cred.Cookie,
	}
	var resp struct {
		Success bool   `json:"success"`
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Nickname string `json:"nickname"`
		} `json:"data"`
	}
	res, err := d.client.DoJSON(ctx, "GET", d.info, h, nil, &resp)
	if err != nil {
		if err == httpx.ErrBadPayload {
			return driver.CredStatus{}, driver.NewErr(driver.KindInterfaceChanged, "UC 账号信息响应不是合法 JSON,疑似接口改版", err)
		}
		return driver.CredStatus{}, driver.NewErr(driver.KindUpstream, "UC 网络请求失败", err)
	}
	_ = res
	if !resp.Success {
		// account/info 无 code 字段,success:false 即登录态失效
		msg := resp.Message
		if msg == "" {
			msg = "登录态失效"
		}
		return driver.CredStatus{Valid: false, Message: msg}, nil
	}
	return driver.CredStatus{Valid: true, Nickname: resp.Data.Nickname, Message: "ok"}, nil
}
