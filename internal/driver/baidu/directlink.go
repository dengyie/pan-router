// 直链链:复用副本/暂存目录 → 转存 → locatedownload/filemetas 取直链 → 过期批量清扫(bdstoken 刷新重试为常态路径)。
package baidu

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/dengyie/panrouter/internal/driver"
)

func (d *Driver) GetDirectLink(ctx context.Context, cred *driver.Credential, ref driver.FileRef) (driver.DirectLink, error) {
	if cred == nil || cred.Cookie == "" {
		return driver.DirectLink{}, driver.NewErr(driver.KindAuthExpired,
			"百度提链需要登录态,请先在「账号管理」添加百度账号 Cookie", nil)
	}
	if ref.Own {
		token, err := d.getBdstoken(ctx, cred, false)
		if err != nil {
			return driver.DirectLink{}, err
		}
		u, err := d.filemetasDlink(ctx, cred.Cookie, token, ref.FID)
		if err != nil {
			return driver.DirectLink{}, err
		}
		return d.linkFrom(cookieHeader(cred.Cookie, ""), u), nil
	}
	if ref.Ext == nil {
		return driver.DirectLink{}, driver.NewErr(driver.KindNotFound, "缺少百度分享上下文,请重新解析", nil)
	}
	// sekey 归一化:新快照存的就是解码形态(verify 已归一化),存量快照存的是
	// 百度返回的编码形态,这里统一成解码形态,避免查询参数双重编码(200025)。
	shareID, uk, sekey := ref.Ext["share_id"], ref.Ext["uk"], normalizeSekey(ref.Ext["sekey"])

	tmp := d.ensureTmpDir(ctx, cred)
	if tmp != "" {
		// 清扫丢到后台:它要现取 bdstoken + 列目录 + 批量删除,不该占用解析请求的
		// 预算,也不该和用户自己的提链抢 pan 限频。放在转存之前、且两条路径共用:
		// 重启后台账已空,只有后续的解析请求才会触发对账——只挂在转存路径上,
		// 命中复用(最常见)就永远不会清理上次进程留下的孤儿副本。
		d.sweepCopies(ctx, cred, tmp)
		// 先查副本台账:命中且未过期就只重取直链,不再转存。
		// 百度把「转存→立刻删除」的循环当刷量(生产实证 2026-11-17:一小时约
		// 20 次即被拉进转存黑名单,errno=9013),复用副本是压掉转存次数最直接
		// 的办法,同时也省掉当天的转存配额。
		if e, ok := d.reuseCopy(cred.Cookie, shareID, ref.FID); ok {
			u, lerr := d.locateDownload(ctx, cred.Cookie, e.path)
			if lerr == nil {
				d.touchCopy(cred.Cookie, shareID, ref.FID)
				return d.linkFrom(cookieHeader(cred.Cookie, e.sekey), u), nil
			}
			token, terr := d.getBdstoken(ctx, cred, false)
			if terr == nil {
				if u, lerr2 := d.filemetasDlink(ctx, cred.Cookie, token, e.fsid); lerr2 == nil {
					d.touchCopy(cred.Cookie, shareID, ref.FID)
					return d.linkFrom(cookieHeader(cred.Cookie, e.sekey), u), nil
				} else {
					lerr = lerr2
				}
			}
			// 只有「副本确实不存在」才丢台账重转:网络抖动/风控/接口异常时副本多半
			// 还在,重转只会白烧一次配额、多一次刷量记录(黑名单风险),如实报错更稳。
			if copyGone(lerr) {
				d.forgetCopy(cred.Cookie, shareID, ref.FID)
			} else {
				if terr != nil {
					return driver.DirectLink{}, terr
				}
				return driver.DirectLink{}, lerr
			}
		}
		if err := d.takeTransferQuota(cred.Cookie); err != nil {
			return driver.DirectLink{}, err
		}
		newFsid, newPath, err := d.transferWithTokenRetry(ctx, cred, shareID, uk, sekey, ref.FID, tmp)
		if err != nil {
			// 转存目录可能被外部删除:丢弃缓存,下次 find-or-create 重建。
			d.forgetTmpDir(cred.Cookie)
			return driver.DirectLink{}, err
		}
		// 台账里的路径日后会作为**批量删除**的目标发给上游,所以入账前必须确认
		// 它真在暂存目录内。newPath 直接取自转存响应的 extra.list[0].to,是上游
		// 输入,不能默认可信:接口改语义或异常响应给出越界路径时,清理会删掉
		// 用户自己的文件,而删除不可逆。此处直接拒绝,不入账。
		if !insideDir(newPath, tmp) {
			d.forgetTmpDir(cred.Cookie)
			return driver.DirectLink{}, driver.NewErr(driver.KindInterfaceChanged,
				"百度转存返回的路径不在暂存目录内,已拒绝入账(疑似接口变更)", nil)
		}
		// 副本留在暂存目录里复用(不再用完即删),过期由 sweepCopies 批量清扫。
		d.rememberCopy(cred.Cookie, shareID, ref.FID, copyEntry{
			fsid: newFsid, path: newPath, sekey: sekey, at: time.Now(),
		})
		// locatedownload 抓包常量(psign 等)若被百度轮换,退回 filemetas 按 fs_id 取链。
		if u, err := d.locateDownload(ctx, cred.Cookie, newPath); err == nil {
			return d.linkFrom(cookieHeader(cred.Cookie, sekey), u), nil
		}
		token, err := d.getBdstoken(ctx, cred, false)
		if err != nil {
			return driver.DirectLink{}, err
		}
		u, err := d.filemetasDlink(ctx, cred.Cookie, token, newFsid)
		if err != nil {
			return driver.DirectLink{}, err
		}
		return d.linkFrom(cookieHeader(cred.Cookie, sekey), u), nil
	}
	return driver.DirectLink{}, driver.NewErr(driver.KindUpstream, "百度暂存目录不可用", nil)
}

// linkFrom 组装 DirectLink:百度直链要求 netdisk UA + 登录 Cookie(实测缺任一项 403)。
func (d *Driver) linkFrom(cookie, u string) driver.DirectLink {
	return driver.DirectLink{
		URL:       u,
		UA:        NetdiskUA,
		Referer:   referer,
		Cookie:    cookie,
		BindIP:    false,
		ExpiresAt: time.Now().Add(linkTTL),
	}
}

// ---- 转存 ----

// ensureTmpDir 按登录态指纹缓存暂存目录路径,不存在则创建 /panrouter_tmp。
func (d *Driver) ensureTmpDir(ctx context.Context, cred *driver.Credential) string {
	key := fingerprint(cred.Cookie)
	d.tmpMu.Lock()
	p := d.tmpDirs[key]
	d.tmpMu.Unlock()
	if p != "" {
		return p
	}
	token, err := d.getBdstoken(ctx, cred, false)
	if err != nil {
		return ""
	}
	if err := d.createDir(ctx, cred.Cookie, token, "/"+tmpDirName); err == nil {
		d.tmpMu.Lock()
		d.tmpDirs[key] = "/" + tmpDirName
		d.tmpMu.Unlock()
		return "/" + tmpDirName
	}
	// 创建失败大概率是「目录已存在」:按名探测确认后再复用。
	for _, rootPath := range d.listRootPaths(ctx, cred.Cookie, token) {
		if rootPath == "/"+tmpDirName {
			d.tmpMu.Lock()
			d.tmpDirs[key] = "/" + tmpDirName
			d.tmpMu.Unlock()
			return "/" + tmpDirName
		}
	}
	return ""
}

func (d *Driver) forgetTmpDir(cookie string) {
	d.tmpMu.Lock()
	delete(d.tmpDirs, fingerprint(cookie))
	d.tmpMu.Unlock()
}

// createDir 在个人网盘根目录下建目录(已存在时接口报错,由调用方按 exist 兜底)。
func (d *Driver) createDir(ctx context.Context, cookie, token, path string) error {
	form := url.Values{}
	form.Set("path", path)
	form.Set("isdir", "1")
	form.Set("size", "")
	form.Set("block_list", "[]")
	form.Set("method", "post")
	form.Set("dataType", "json")
	u := d.base + "/api/create?a=commit&channel=chunlei&web=1&app_id=" + appID +
		"&clienttype=0&bdstoken=" + url.QueryEscape(token)
	var out struct {
		Errno  int    `json:"errno"`
		ErrMsg string `json:"errmsg"`
	}
	_, err := d.call(ctx, "POST", u, form, map[string]string{"cookie": cookie, "referer": "https://pan.baidu.com/disk/main"}, &out)
	if err != nil {
		return err
	}
	if err := mustOK(out.Errno, out.ErrMsg); err != nil {
		return err
	}
	return nil
}

// listRootPaths 返回个人网盘根目录下的路径列表(供 tmpdir 存在性探测)。
func (d *Driver) listRootPaths(ctx context.Context, cookie, token string) []string {
	u := d.base + "/api/list?clienttype=0&app_id=" + appID +
		"&web=1&order=time&desc=1&dir=" + url.QueryEscape("/") + "&num=100&page=1"
	var out struct {
		Errno  int    `json:"errno"`
		ErrMsg string `json:"errmsg"`
		List   []struct {
			Path string `json:"path"`
		} `json:"list"`
	}
	if _, err := d.call(ctx, "GET", u, nil, map[string]string{"cookie": cookie}, &out); err != nil {
		return nil
	}
	paths := make([]string, 0, len(out.List))
	for _, it := range out.List {
		paths = append(paths, it.Path)
	}
	return paths
}

// transferWithTokenRetry 执行转存;bdstoken 失效(errno=105/-6)时重取一次。
func (d *Driver) transferWithTokenRetry(ctx context.Context, cred *driver.Credential, shareID, uk, sekey, fsid, toDir string) (string, string, error) {
	token, err := d.getBdstoken(ctx, cred, false)
	if err != nil {
		return "", "", err
	}
	newFsid, newPath, err := d.transfer(ctx, cred.Cookie, shareID, uk, sekey, fsid, toDir, token)
	if err != nil && isBdstoken(err) {
		d.forgetBdstoken(cred.Cookie)
		if token, err = d.getBdstoken(ctx, cred, true); err != nil {
			return "", "", err
		}
		newFsid, newPath, err = d.transfer(ctx, cred.Cookie, shareID, uk, sekey, fsid, toDir, token)
	}
	return newFsid, newPath, err
}

func isBdstoken(err error) bool {
	var de *driver.Error
	if !errors.As(err, &de) {
		return false
	}
	return errors.Is(de, errBdstoken)
}

// transfer 转存分享中的单个文件到 toDir,返回转存后的新 fs_id 与新路径。
// ondup=newcopy:同名文件一律复制新副本,不会覆盖旧文件。
func (d *Driver) transfer(ctx context.Context, cookie, shareID, uk, sekey, fsid, toDir, token string) (string, string, error) {
	form := url.Values{}
	form.Set("fsidlist", `["`+fsid+`"]`)
	form.Set("path", toDir)
	u := d.base + "/share/transfer?shareid=" + url.QueryEscape(shareID) +
		"&from=" + url.QueryEscape(uk) +
		"&channel=chunlei&sekey=" + url.QueryEscape(sekey) +
		"&ondup=newcopy&web=1&app_id=" + appID +
		"&bdstoken=" + url.QueryEscape(token) + "&clienttype=0"
	var out struct {
		Errno   int    `json:"errno"`
		ErrMsg  string `json:"errmsg"`
		ShowMsg string `json:"show_msg"`
		Extra   struct {
			List []struct {
				ToFsID string `json:"to_fs_id"`
				To     string `json:"to"`
			} `json:"list"`
		} `json:"extra"`
	}
	_, err := d.call(ctx, "POST", u, form, map[string]string{
		"cookie":  cookieHeader(cookie, sekey),
		"origin":  "https://pan.baidu.com",
		"referer": "https://pan.baidu.com/s/",
	}, &out)
	if err != nil {
		return "", "", err
	}
	// 转存失败时百度常把真正的原因放在 show_msg,errmsg 留空:
	// 生产实证 200025 只有 show_msg「提取码输入错误,请重试」。不回填的话
	// 错误分类只能看到空文案,用户和维护者都无从判断。
	if out.ErrMsg == "" {
		out.ErrMsg = out.ShowMsg
	}
	if err := mustOK(out.Errno, out.ErrMsg); err != nil {
		return "", "", err
	}
	if len(out.Extra.List) == 0 || out.Extra.List[0].ToFsID == "" {
		return "", "", driver.NewErr(driver.KindInterfaceChanged, "百度转存响应缺少新文件 fs_id", nil)
	}
	first := out.Extra.List[0]
	to := first.To
	if to == "" {
		to = strings.TrimRight(toDir, "/") + "/" + fsid
	}
	return first.ToFsID, to, nil
}

// ---- 取直链 ----

// locateDownload 走客户端协议的高带宽直链(自带 sign,无需计算)。
// 抓包常量(psign/rand/devuid 等)有登录态即可复用;百度轮换时返回错误,由调用方退 filemetas。
func (d *Driver) locateDownload(ctx context.Context, cookie, path string) (string, error) {
	now := time.Now().Unix()
	u := d.pcs + "/rest/2.0/pcs/file" +
		"?method=locatedownload" +
		"&app_id=" + appID +
		"&clienttype=17&ver=4.0" +
		"&ant=1&check_blue=1&es=1&esl=1&apn_id=1_-1" +
		"&freeisp=0&queryfree=0&use=1&dtype=1&eck=1&ehps=1" +
		"&err_ver=1.0&network_type=WIFI&channel=0" +
		"&path=" + url.QueryEscape(path) +
		"&time=" + itoa(int(now)) +
		"&rand=5ed606e9da222cde0474cdf70eda884b" +
		"&devuid=0F1E9FC2E084472DA5A61C4CF4C759AF" +
		"&cuid=0F1E9FC2E084472DA5A61C4CF4C759AF" +
		"&deviceid=348642637967375013" +
		"&psign=860a071f77c860e8cea06e4e54c518f3" +
		"&version=2.2.111.34&version_app=12.24.6&vip=0"
	req, err := http.NewRequestWithContext(ctx, "POST", u, strings.NewReader("0"))
	if err != nil {
		return "", driver.NewErr(driver.KindUpstream, "构造百度直链请求失败", err)
	}
	req.Header.Set("User-Agent", NetdiskUA)
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := d.client.Do(req)
	if err != nil {
		return "", driver.NewErr(driver.KindUpstream, "百度 locatedownload 网络请求失败", err)
	}
	var out struct {
		Errno  int    `json:"errno"`
		ErrMsg string `json:"errmsg"`
		Urls   []struct {
			URL     string `json:"url"`
			Encrypt int    `json:"encrypt"`
		} `json:"urls"`
	}
	if len(res.Body) > 0 {
		if err := json.Unmarshal(res.Body, &out); err != nil {
			return "", driver.NewErr(driver.KindInterfaceChanged, "百度 locatedownload 响应不是合法 JSON", err)
		}
	}
	if out.Errno != 0 {
		return "", mustOK(out.Errno, out.ErrMsg)
	}
	var candidate string
	for _, it := range out.Urls {
		if it.URL == "" {
			continue
		}
		// encrypt=0 明文 CDN 最稳;没有则退回第一个 https 候选。
		if it.Encrypt == 0 && strings.HasPrefix(it.URL, "https") {
			return it.URL, nil
		}
		if candidate == "" || strings.HasPrefix(it.URL, "https") {
			candidate = it.URL
		}
	}
	if candidate != "" {
		return candidate, nil
	}
	return "", driver.NewErr(driver.KindInterfaceChanged, "百度 locatedownload 未返回可用直链", nil)
}

// filemetasDlink 按 fs_id 从 filemetas 取 dlink(个人文件/转存后文件皆可)。
func (d *Driver) filemetasDlink(ctx context.Context, cookie, token, fsid string) (string, error) {
	fsids := `["` + fsid + `"]`
	u := d.base + "/api/filemetas?dlink=1&fsids=" + url.QueryEscape(fsids) +
		"&bdstoken=" + url.QueryEscape(token) +
		"&clienttype=0&app_id=" + appID + "&web=1"
	var out struct {
		Errno  int    `json:"errno"`
		ErrMsg string `json:"errmsg"`
		Info   []struct {
			Dlink string `json:"dlink"`
		} `json:"info"`
	}
	if _, err := d.call(ctx, "GET", u, nil, map[string]string{"cookie": cookie}, &out); err != nil {
		return "", err
	}
	if err := mustOK(out.Errno, out.ErrMsg); err != nil {
		return "", err
	}
	if len(out.Info) == 0 || out.Info[0].Dlink == "" {
		return "", driver.NewErr(driver.KindInterfaceChanged, "百度 filemetas 未返回 dlink", nil)
	}
	return out.Info[0].Dlink, nil
}

// ---- 转存副本台账 ----
//
// 为什么不再「用完即删」:百度把高频「转存→立刻删除」当刷量。生产实证
// (2026-11-17)一小时内约 20 次转存+删除后,账号被直接拉黑转存权限
// (/share/transfer 回 errno=9013 hit black uid share transfer),此后同一分享
// 在别的账号/裸 Python 上都能正常转存。所以副本改为:在 copyTTL 内复用
// (只重取直链,不消耗转存配额),过期后合并成一次批量删除。

// copyTTL 是副本的**闲置**超时,不是「转存后的绝对寿命」:每次复用都会续期。
//
// ★ 必须显著大于 linkTTL(45 分钟):直链缓存到期会重新调 GetDirectLink,若副本
// 按「转存时刻 + 45 分钟」判过期,续签请求必然正好踩在过期边界上重新转存,复用
// 路径形同虚设(仍然每个直链周期转存一次)。4 小时覆盖常见会话时长,又不至于把
// 转存副本长期占着用户网盘空间。
const copyTTL = 4 * time.Hour

// maxCopiesPerAccount 单账号台账上界:防超长分享把暂存目录撑爆,超出按最旧优先清。
const maxCopiesPerAccount = 80

// copySweepInterval 同账号清扫节流:过期副本攒着一起删,避免又退化成一链一删。
const copySweepInterval = 10 * time.Minute

// copySweepBudget 后台清扫的独立预算:清扫不跟随任何解析请求的生命周期。
const copySweepBudget = 30 * time.Second

// copyEntry 是一条已转存副本的台账项。
type copyEntry struct {
	fsid  string    // 转存后的 fs_id(filemetas 取直链用)
	path  string    // 转存后的完整路径(locatedownload 取直链 / 删除用)
	sekey string    // 分享验证标识:重取直链时 Cookie 要带同一个 BDCLND
	at    time.Time // 最近使用时间(转存或复用命中时刷新)
}

// sweepItem 是一条待清扫的台账项(台账键 + 副本路径 + 快照时的 at)。
type sweepItem struct {
	key  string
	path string
	at   time.Time
}

// copyKey 台账键:同账号下按「分享 + 文件」区分,不同分享的同名文件不会串。
func copyKey(cookie, shareID, fsid string) string {
	return fingerprint(cookie) + "|" + shareID + "|" + fsid
}

// reuseCopy 查台账;命中且未闲置超时返回副本,调用方只重取直链即可。
//
// 命中即续租(at 刷新为当前时间):取直链要串行往返 locatedownload,失败还要
// 现取 bdstoken + filemetas。若这段窗口里 at 仍是旧值,并发清扫会把这个**正在
// 被复用**的副本判成闲置并删掉,请求随后报「副本不存在」,白白重转一次。
func (d *Driver) reuseCopy(cookie, shareID, fsid string) (copyEntry, bool) {
	k := copyKey(cookie, shareID, fsid)
	now := time.Now()
	d.copyMu.Lock()
	defer d.copyMu.Unlock()
	e, ok := d.copies[k]
	if !ok || now.Sub(e.at) > copyTTL {
		return copyEntry{}, false
	}
	e.at = now
	d.copies[k] = e
	return e, true
}

func (d *Driver) rememberCopy(cookie, shareID, fsid string, e copyEntry) {
	d.copyMu.Lock()
	d.copies[copyKey(cookie, shareID, fsid)] = e
	d.copyMu.Unlock()
}

// touchCopy 刷新最近使用时间。不刷新的话,天天在用的副本也会在转存 4 小时后被
// 判闲置 —— 然后下次请求再转存一次,正是要压掉的刷量。
func (d *Driver) touchCopy(cookie, shareID, fsid string) {
	k := copyKey(cookie, shareID, fsid)
	d.copyMu.Lock()
	if e, ok := d.copies[k]; ok {
		e.at = time.Now()
		d.copies[k] = e
	}
	d.copyMu.Unlock()
}

func (d *Driver) forgetCopy(cookie, shareID, fsid string) {
	d.copyMu.Lock()
	delete(d.copies, copyKey(cookie, shareID, fsid))
	d.copyMu.Unlock()
}

// dropCopies 批量移除台账项(删除成功/确认远端不存在后调用)。
//
// 按 at 做「比较并删除」:清扫在后台跑,期间同一个键可能已经因为复用失败被重转
// 成了一份新副本并重新入账 —— 盲删会把新副本的记录抹掉,留下无人认领的孤儿。
// at 不同就说明台账已被更新,保留。
func (d *Driver) dropCopies(items []sweepItem) {
	if len(items) == 0 {
		return
	}
	d.copyMu.Lock()
	for _, it := range items {
		if e, ok := d.copies[it.key]; ok && e.at.Equal(it.at) {
			delete(d.copies, it.key)
		}
	}
	d.copyMu.Unlock()
}

// splitGone 把台账里的闲置项分成「远端仍在」(keep)与「远端已删」(gone)。
//
// complete=false 表示目录列表被翻页上界截断:此时任何「不在列表里」都不可信,
// 全部保留 —— 丢掉台账等于永久放弃清理它们(副本还在,却再没人认领)。
func splitGone(idle []sweepItem, present map[string]struct{}, complete bool) (keep, gone []sweepItem) {
	if !complete {
		return idle, nil
	}
	keep = idle[:0]
	for _, it := range idle {
		if _, ok := present[it.path]; ok {
			keep = append(keep, it)
		} else {
			gone = append(gone, it)
		}
	}
	return keep, gone
}

// isRiskControl 判断错误是否为上游风控/安全验证拒绝(重试无意义,应退避)。
func isRiskControl(err error) bool {
	var de *driver.Error
	return errors.As(err, &de) && de.Kind == driver.KindRiskControl
}

// copyGone 判断复用失败是否属于「副本确实不在了」。只有这种失败才值得丢台账
// 重新转存;网络抖动/风控/接口异常都保留台账,下次继续尝试复用。
func copyGone(err error) bool {
	var de *driver.Error
	if !errors.As(err, &de) {
		return false
	}
	switch de.Kind {
	case driver.KindNotFound, driver.KindShareGone:
		return true
	}
	// locatedownload/filemetas 对「文件已不在」的 errno 没有实证(可能复用
	// errno=2 参数错误),按文案兜底识别。宁可多认一次:漏认会让一个已删副本把
	// 台账永久钉住 —— 每次提链都失败,却永远不重转。
	h := de.UserHint
	return strings.Contains(h, "不存在") || strings.Contains(h, "已删除")
}

// sweepCopies 在后台清扫过期副本,同账号至多每 copySweepInterval 一次。
//
// 三个约束决定了这个形状:
//  1. **不能占请求路径**:清扫要现取 bdstoken、列目录、发批量删除,和用户的提链
//     抢同一份限频与 90s 预算,放在 GetDirectLink 里等于给每次解析加尾延迟。
//  2. **远端目录才是真源**:台账在内存里,进程一重启就空了(每次发版都重启)。
//     只看台账,遗留副本会永远留在用户网盘里——转存用 ondup=newcopy,每重转一份
//     就多一份,孤儿无限累积并持续吃配额。
//  3. **删除成功才丢台账**:删失败还提前忘掉台账,云端副本就失去唯一记录,以后
//     没人会再清它。仅「超上限」的台账项例外——内存必须有界。
func (d *Driver) sweepCopies(ctx context.Context, cred *driver.Credential, dir string) {
	if cred == nil || cred.Cookie == "" || dir == "" {
		return
	}
	fp := fingerprint(cred.Cookie)
	now := time.Now()
	d.copyMu.Lock()
	if d.sweepAt == nil {
		d.sweepAt = map[string]time.Time{}
	}
	if now.Sub(d.sweepAt[fp]) < copySweepInterval {
		d.copyMu.Unlock()
		return
	}
	// 先占位再异步执行:并发请求里只有一个会真正发起清扫;失败也按间隔重试,
	// 不会因为一次失败变成每个请求都扫。
	d.sweepAt[fp] = now
	prefix := fp + "|"
	keys := make([]string, 0, len(d.copies))
	for k := range d.copies {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	// 最旧的排前面:先删闲置超时的,超上限时补刀最旧的。
	sort.Slice(keys, func(i, j int) bool { return d.copies[keys[i]].at.Before(d.copies[keys[j]].at) })
	overflow := len(keys) - maxCopiesPerAccount
	var forced, idle []sweepItem
	live := make(map[string]struct{}, len(keys))
	for i, k := range keys {
		e := d.copies[k]
		switch {
		case i < overflow:
			forced = append(forced, sweepItem{key: k, path: e.path, at: e.at})
		case now.Sub(e.at) > copyTTL:
			idle = append(idle, sweepItem{key: k, path: e.path, at: e.at})
		default:
			// 仍在使用的副本:即使远端 mtime 很旧也不许删(复用只重取直链,
			// 不会更新文件 mtime,靠 at 判活)。
			if e.path != "" {
				live[e.path] = struct{}{}
			}
		}
	}
	d.copyMu.Unlock()

	d.sweepWG.Add(1)
	go func() {
		defer d.sweepWG.Done()
		// 后台 goroutine 的 panic 不能掀翻进程。
		defer func() { _ = recover() }()
		cleanCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), copySweepBudget)
		defer cancel()
		token, err := d.getBdstoken(cleanCtx, cred, false)
		if err != nil {
			d.dropCopies(forced)
			return
		}
		entries, complete, lerr := d.listDir(cleanCtx, cred.Cookie, dir)
		if lerr == nil {
			present := make(map[string]struct{}, len(entries))
			for _, it := range entries {
				present[it.Path] = struct{}{}
			}
			var gone []sweepItem
			idle, gone = splitGone(idle, present, complete)
			d.dropCopies(gone)
		}
		// 台账里出现越界路径只可能是上游异常(入账处已拦,这里兜历史/新增路径):
		// 这种项永远不该由我们删除,也不该继续占台账——否则每轮清扫都会重试它。
		var bad []sweepItem
		dropOutside := func(items []sweepItem) []sweepItem {
			keep := items[:0]
			for _, it := range items {
				if insideDir(it.path, dir) {
					keep = append(keep, it)
				} else {
					bad = append(bad, it)
				}
			}
			return keep
		}
		forced, idle = dropOutside(forced), dropOutside(idle)
		d.dropCopies(bad)
		paths := make([]string, 0, len(forced)+len(idle)+len(entries))
		seen := make(map[string]struct{}, len(forced)+len(idle))
		add := func(p string) {
			if p == "" {
				return
			}
			// 删除不可逆,路径必须确实在暂存目录内。台账 path 来自上游转存响应
			// (extra.list[0].to),入账处已校验;这里再挡一道,任何将来新增的
			// 入账路径都不会绕过。
			if !insideDir(p, dir) {
				return
			}
			if _, ok := live[p]; ok {
				return
			}
			if _, ok := seen[p]; ok {
				return
			}
			seen[p] = struct{}{}
			paths = append(paths, p)
		}
		for _, it := range forced {
			add(it.path)
		}
		for _, it := range idle {
			add(it.path)
		}
		if lerr == nil {
			// 台账外的遗留副本(重启/换 Cookie 造成):按远端 mtime 兜底清理。
			cutoff := time.Now().Add(-copyTTL)
			for _, it := range entries {
				if it.IsDir != 0 || it.ServerMtime <= 0 {
					continue
				}
				if time.Unix(it.ServerMtime, 0).Before(cutoff) {
					add(it.Path)
				}
			}
		}
		if len(paths) == 0 {
			d.dropCopies(forced)
			return
		}
		if derr := d.deletePaths(cleanCtx, cred.Cookie, token, paths); derr != nil {
			// 删除失败:只丢超上限的台账(保证内存有界),其余留着下次重试。
			d.dropCopies(forced)
			// 风控/安全验证类失败(errno=132,authwidget.safetpl)重试没有意义,
			// 按普通周期再戳一次只是拿同一个请求反复喂风控。把下次清扫推后:
			// 既省调用,也避免因「持续异常流量」加深账号的风险画像。
			if isRiskControl(derr) {
				d.copyMu.Lock()
				d.sweepAt[fp] = time.Now().Add(copySweepInterval * 5)
				d.copyMu.Unlock()
			}
			return
		}
		d.dropCopies(append(forced, idle...))
	}()
}

// dirEntry 是 xpan file 列目录的条目子集:清理只需要路径、类型与服务器时间。
type dirEntry struct {
	Path        string `json:"path"`
	IsDir       int    `json:"isdir"`
	ServerMtime int64  `json:"server_mtime"`
}

// dirListNum 暂存目录单页条数(台账上限 80,单页足够;超大目录靠翻页)。
const dirListNum = 1000

// dirListMax 是单次清扫最多看的条数。触顶返回 complete=false:此时列表是截断的,
// 调用方不得用「不在列表里」推断远端已删(否则会丢掉仍在的台账项)。下一轮清扫
// 会重新从最新一页开始,逐轮推进。
const dirListMax = 10000

// listDir 列出暂存目录内容(清理的远端真源),翻页直到不满一页。
//
// 走 xpan `/rest/2.0/xpan/file?method=list`,不走 web 的 `/api/list`:后者即便
// 登录态有效也恒回 `{"errno":8888,"errmsg":"test"}`(生产实证 2026-11-17,用
// 驱动同款 Cookie/bdstoken 与两套 UA 复刻四种参数组合皆然),清扫若以它为
// 真源则永远拿到空列表 —— 重启遗留的孤儿副本一个也清不掉,还会把它们全判成
// 「远端不存在」而丢掉台账。
//
// ★ 必须翻页:单页 limit 的旧实现把「一页」当「全量」。目录超过一页时,最旧的
// 台账项不在结果里 → 被误判为远端已删、丢台账,又不进删除列表,变成无人认领的
// 永久孤儿(同时让 maxCopiesPerAccount 的内存上界失效)。complete 就是这个
// 不确定性的显式出口。
func (d *Driver) listDir(ctx context.Context, cookie, dir string) (entries []dirEntry, complete bool, err error) {
	for start := 0; ; start += dirListNum {
		page, err := d.listDirPage(ctx, cookie, dir, start)
		if err != nil {
			return nil, false, err
		}
		entries = append(entries, page...)
		if len(page) < dirListNum {
			return entries, true, nil
		}
		if start+dirListNum >= dirListMax {
			return entries, false, nil
		}
	}
}

func (d *Driver) listDirPage(ctx context.Context, cookie, dir string, start int) ([]dirEntry, error) {
	u := d.base + "/rest/2.0/xpan/file?method=list&dir=" + url.QueryEscape(dir) +
		"&order=time&desc=1&start=" + itoa(start) + "&limit=" + itoa(dirListNum) + "&web=1"
	var out struct {
		Errno  int        `json:"errno"`
		ErrMsg string     `json:"errmsg"`
		List   []dirEntry `json:"list"`
	}
	if _, err := d.call(ctx, "GET", u, nil, map[string]string{"cookie": cookie}, &out); err != nil {
		return nil, err
	}
	if err := mustOK(out.Errno, out.ErrMsg); err != nil {
		return nil, err
	}
	return out.List, nil
}

// insideDir 判断 p 是否确实位于 dir 之内(严格子路径)。
//
// 批量删除的目标路径不能只看「上游说是这里」:删除不可逆,一旦上游改语义或
// 返回越界路径(含 `..` 穿越),清理就会删掉用户自己的文件。故同时要求前缀
// 匹配且路径段里没有 `.`/`..`/空段。
func insideDir(p, dir string) bool {
	base := strings.TrimRight(dir, "/")
	if base == "" || p == base || !strings.HasPrefix(p, base+"/") {
		return false
	}
	for _, seg := range strings.Split(strings.TrimPrefix(p, base+"/"), "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// deletePaths 批量删除暂存目录内的副本,返回本次删除是否被接受。
func (d *Driver) deletePaths(ctx context.Context, cookie, token string, paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	raw, err := json.Marshal(paths)
	if err != nil {
		return err
	}
	form := url.Values{}
	form.Set("filelist", string(raw))
	u := d.base + "/api/filemanager?async=2&onnest=fail&opera=delete&bdstoken=" +
		url.QueryEscape(token) + "&newVerify=1&clienttype=0&app_id=" + appID + "&web=1"
	var out struct {
		Errno  int    `json:"errno"`
		ErrMsg string `json:"errmsg"`
	}
	if _, err := d.call(ctx, "POST", u, form, map[string]string{
		"cookie": cookie,
	}, &out); err != nil {
		return err
	}
	return mustOK(out.Errno, out.ErrMsg)
}
