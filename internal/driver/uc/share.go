// 分享解析:ResolveShare 与目录遍历(v2/detail POST JSON,列表在 detail_info.list)。
// 预算上界与截断标记口径与 quark/pan123 一致。
package uc

import (
	"context"
	"encoding/json"

	"github.com/dengyie/panrouter/internal/driver"
)

func (d *Driver) ResolveShare(ctx context.Context, share driver.ShareLink, cred *driver.Credential) ([]driver.FileNode, error) {
	m := pwdIDRe.FindStringSubmatch(share.URL)
	if m == nil {
		return nil, driver.NewErr(driver.KindNotFound, "无法识别的 UC 分享链接", nil)
	}
	pwdID := m[1]
	st, err := d.stoken(ctx, pwdID, share.Pwd, cred)
	if err != nil {
		return nil, err
	}
	ext := map[string]string{"pwd_id": pwdID, "stoken": st, "pwd": share.Pwd}
	bud := &shareWalkBudget{files: maxShareFiles, dirs: maxShareDirs}
	nodes, err := d.walkShare(ctx, cred, "0", "", 0, ext, map[string]struct{}{}, bud)
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

// listShareDir 分页列出分享内某一目录(v2/detail POST JSON;子目录追加 pdir_fid,根目录不传;
// 列表在 data.detail_info.list,share_fid_token 与 stoken 绑定)。
func (d *Driver) listShareDir(ctx context.Context, cred *driver.Credential, pwdID, passcode, st, pdirFID string) ([]ucFile, error) {
	var files []ucFile
	for page := 1; page <= 100; page++ {
		if err := ctx.Err(); err != nil {
			return nil, driver.NewErr(driver.KindUpstream, "分享目录遍历已取消", err)
		}
		body := map[string]any{
			"pwd_id":                 pwdID,
			"passcode":               passcode,
			"force":                  0,
			"page":                   page,
			"size":                   50,
			"fetch_banner":           1,
			"fetch_share":            1,
			"fetch_total":            1,
			"sort":                   "file_type:asc,file_name:asc",
			"banner_platform":        "other",
			"web_platform":           "windows",
			"fetch_error_background": 1,
		}
		if pdirFID != "" && pdirFID != "0" {
			body["pdir_fid"] = pdirFID
		}
		var resp apiResp
		u := d.base + "/1/clouddrive/share/sharepage/v2/detail?" + prQuery + "&ve=2.5.20"
		if _, err := d.call(ctx, "POST", u, body, cred, &resp); err != nil {
			return nil, err
		}
		if !ok(&resp) {
			return nil, d.classify(resp.Code, resp.Message)
		}
		var data struct {
			DetailInfo struct {
				List []ucFile `json:"list"`
			} `json:"detail_info"`
		}
		if err := json.Unmarshal(resp.Data, &data); err != nil {
			return nil, driver.NewErr(driver.KindInterfaceChanged, "UC 响应结构变化,解析失败", err)
		}
		files = append(files, data.DetailInfo.List...)
		if len(data.DetailInfo.List) == 0 {
			break
		}
	}
	return files, nil
}

// walkShare 递归展开分享目录,只返回文件(名称带相对路径)。
func (d *Driver) walkShare(ctx context.Context, cred *driver.Credential, pdirFID, prefix string, depth int, ext map[string]string, seen map[string]struct{}, bud *shareWalkBudget) ([]driver.FileNode, error) {
	if err := ctx.Err(); err != nil {
		return nil, driver.NewErr(driver.KindUpstream, "分享目录遍历已取消", err)
	}
	if depth > maxShareDepth || bud.files <= 0 {
		bud.truncated = true
		return nil, nil
	}
	entries, err := d.listShareDir(ctx, cred, ext["pwd_id"], ext["pwd"], ext["stoken"], pdirFID)
	if err != nil {
		return nil, err
	}
	var nodes []driver.FileNode
	var dirs []ucFile
	for _, f := range entries {
		if f.FID == "" {
			continue
		}
		if _, ok := seen[f.FID]; ok {
			continue
		}
		seen[f.FID] = struct{}{}
		if f.Dir {
			dirs = append(dirs, f)
			continue
		}
		if bud.files <= 0 {
			bud.truncated = true
			break
		}
		bud.files--
		// 提链上下文:pwd_id/stoken/pwd + fid_token(与 stoken 绑定,download 校验必需)
		nodeExt := map[string]string{
			"pwd_id": ext["pwd_id"], "stoken": ext["stoken"], "pwd": ext["pwd"],
			"fid_token": f.ShareFIDToken,
		}
		nodes = append(nodes, driver.FileNode{
			FID: f.FID, Name: joinSharePath(prefix, f.FileName), Size: f.Size, IsDir: false, Ext: nodeExt,
		})
	}
	for _, dir := range dirs {
		if bud.dirs <= 0 || bud.files <= 0 || depth >= maxShareDepth {
			bud.truncated = true
			break
		}
		bud.dirs--
		kids, err := d.walkShare(ctx, cred, dir.FID, joinSharePath(prefix, dir.FileName), depth+1, ext, seen, bud)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, kids...)
	}
	return nodes, nil
}
