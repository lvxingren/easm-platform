package web

import "strings"

// scanDetailInitialResults 是执行详情首屏渲染的结果硬上限。
// 即使某次执行有数十万行结果，首屏也只装载这一页，其余由页面内游标补齐，
// 避免把整张结果表一次性读进内存、拼进 HTML。
const scanDetailInitialResults = 200

// isCapacityRejection 判断扫描错误文本是否为容量预检拒绝。
func isCapacityRejection(errText string) bool {
	return strings.Contains(errText, "容量预检")
}

// capacitySuggestions 从容量预检错误文本推导可操作的调整建议。
// 原始错误文本始终由页面与 API 原样返回（不吞错误），建议只作为补充说明。
func capacitySuggestions(errText string) []string {
	if !isCapacityRejection(errText) {
		return nil
	}
	suggestions := []string{
		"把「系统设置 → naabu 扫描参数 → 单次任务超时」提高到错误提示中的分钟数：全端口 1-65535 扫描在默认 60 分钟内通常无法完成。",
		"提高「平台总速率预算」或单进程 naabu 速率后重试；容量预检只会按预算收敛并发，不会自动放大配置。",
		"降低 naabu 重试次数：耗时估算按「重试次数 + 1」倍发包计算。",
		"缩小端口范围：改用常用端口 top-1000 或自定义端口，而不是全端口扫描。",
		"拆分目标：减少单次执行的目标数量，分多次执行。",
	}
	if strings.Contains(errText, "文件描述符") || strings.Contains(errText, "ulimit") {
		suggestions = append(suggestions, "提高服务运行账号的 ulimit -n（建议至少 8192）后重启服务，再重新启动扫描。")
	}
	if strings.Contains(errText, "可用空间") {
		suggestions = append(suggestions, "清理数据目录中的旧扫描产物（batch_*.out / batch_*_targets.txt）或扩容磁盘后重试。")
	}
	return suggestions
}
