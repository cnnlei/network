package main

import (
	"bufio"
	"log"
	"net/http"
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
	log.Println("[Updater] 后台IP名单更新服务已启动，每分钟检查一次。")
	u.ticker = time.NewTicker(1 * time.Minute)
	go func() {
		// 立即执行一次
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

// runUpdateCycle 检查所有需要更新的IP名单并执行更新
func (u *Updater) runUpdateCycle() {
	configMutex.RLock()
	listsToUpdate := make(map[string]*IPListConfig)
	// 只更新 country_ip_lists 分类下的名单
	for name, listConfig := range currentConfig.IPLists.CountryIPLists {
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

// updateList 更新单个IP名单
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
	
	u.ipFilterManager.UpdateDynamicList(name, newIPs)
	log.Printf("[Updater] 名单 [%s] 已成功更新，包含 %d 个IP/CIDR。", name, len(newIPs))
	return nil
}

// fetchIPsFromURL 从给定的URL下载并解析IP地址列表
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