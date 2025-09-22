package main

import (
	"bufio"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
)

// Updater 负责后台定时更新IP名单
type Updater struct {
	ipFilterManager *IPFilterManager
	ticker          *time.Ticker
	stopChan        chan struct{}
}

func NewUpdater(ipFilterManager *IPFilterManager) *Updater {
	return &Updater{
		ipFilterManager: ipFilterManager,
		stopChan:        make(chan struct{}),
	}
}

func (u *Updater) Start() {
	updateInterval := 7 * 24 * time.Hour
	log.Printf("[Updater] 后台IP名单更新服务已启动，每 %v 检查一次。", updateInterval)
	u.ticker = time.NewTicker(updateInterval)
	go func() {
		u.runUpdateCycle()

		for {
			select {
			case <-u.ticker.C:
				u.runUpdateCycle()
			case <-u.stopChan:
				u.ticker.Stop()
				return
			}
		}
	}()
}

func (u *Updater) Stop() {
	log.Println("[Updater] 正在停止后台IP名单更新服务...")
	close(u.stopChan)
}

func (u *Updater) runUpdateCycle() {
	configMutex.RLock()
	listsToUpdate := make(map[string]*IPListConfig)
	for name, listConfig := range currentConfig.IPLists.CountryIPLists {
		listsToUpdate[name] = listConfig
	}
	for name, listConfig := range currentConfig.IPLists.UrlIpSets {
		listsToUpdate[name] = listConfig
	}
	configMutex.RUnlock()

	if len(listsToUpdate) == 0 {
		return
	}

	log.Printf("[Updater] 发现 %d 个需要更新的国家/URL IP名单，开始更新...", len(listsToUpdate))

	var g errgroup.Group
	for name, listConfig := range listsToUpdate {
		name := name
		listConfig := listConfig

		g.Go(func() error {
			return u.updateList(name, listConfig)
		})
	}

	if err := g.Wait(); err != nil {
		log.Printf("[Updater] 更新IP名单时发生错误: %v", err)
	} else {
		log.Println("[Updater] 所有动态名单更新周期完成。")
	}
}

func (u *Updater) updateList(name string, listConfig *IPListConfig) error {
	var newIPs []string
	var err error
	sourceUrl := listConfig.Source

	if listConfig.Type == "country" {
		sourceUrl = "https://www.ipdeny.com/ipblocks/data/countries/" + strings.ToLower(listConfig.Source) + ".zone"
	}

	newIPs, err = fetchIPsFromURL(sourceUrl)
	if err != nil {
		log.Printf("[Updater] 从 [%s] 获取名单 [%s] 失败: %v", sourceUrl, name, err)
		return err
	}

	updateTime := time.Now()

	configMutex.RLock()
	ipListDir := currentConfig.Settings.IPListDirectory
	configMutex.RUnlock()

	if ipListDir != "" {
		filePath := filepath.Join(ipListDir, name+".txt")
		content := strings.Join(newIPs, "\n")
		err := os.WriteFile(filePath, []byte(content), 0644)
		if err != nil {
			log.Printf("[Updater] 无法将名单 [%s] 写入文件 [%s]: %v", name, filePath, err)
		} else {
			log.Printf("[Updater] 名单 [%s] 已成功保存到文件: %s", name, filePath)
		}
	}
	
	u.ipFilterManager.UpdateDynamicList(name, newIPs, updateTime)
	log.Printf("[Updater] 名单 [%s] 已成功更新，包含 %d 个IP/CIDR。", name, len(newIPs))
	return nil
}

func fetchIPsFromURL(url string) ([]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var ips []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			ips = append(ips, line)
		}
	}
	return ips, scanner.Err()
}