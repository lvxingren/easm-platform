//go:build linux || darwin

package scanner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// 本文件提供 fake naabu wrapper 使用的“路径哨兵”：一段受控 Go 代码，而不是 shell 通配。
//
// 为什么不能用 shell 判断路径安全：
//   - shell 的 case 通配 `data/scan_*/batch_*.out` 里，`*` 可以跨斜杠匹配，
//     `data/scan_99/../../../../batch_escape.out` 会被误判为合法产物路径；
//   - shell 也没有内置的 realpath/符号链接解析能力，无法证明路径仍在临时根目录内。
//
// 因此 wrapper 在 exec 会写文件的脚本体之前，先调用本哨兵：
// 哨兵对 -list / -o 的取值做逐段规范化、形态校验、逐段符号链接检查，并断言真实路径
// 仍在临时根目录内；任何违规都以 96 退出，wrapper 立即拒绝，重定向与文件创建都不会发生。
//
// 哨兵复用当前测试二进制（设置环境变量后由 init 分流），无需在测试运行时编译额外程序。

const (
	// fakePathGuardEnv 标记当前进程是被 wrapper 调起的路径哨兵子进程。
	fakePathGuardEnv = "EASM_SCANNER_FAKE_PATH_GUARD"
	// fakePathGuardBinEnv 是哨兵可执行文件（测试二进制）的绝对路径，由测试侧导出。
	fakePathGuardBinEnv = "EASM_SCANNER_FAKE_PATH_GUARD_BIN"
	// fakePathGuardRootEnv 是临时根目录：所有批次产物都必须严格位于其内。
	fakePathGuardRootEnv = "EASM_SCANNER_FAKE_ROOT"
	// fakePathGuardCode 与 wrapper 的拒绝码保持一致。
	fakePathGuardCode = 96
)

// fakeListPattern / fakeOutPattern 只放行生产代码真实生成的批次产物名：
// data/scan_<数字>/batch_<数字>_targets.txt 与 data/scan_<数字>/batch_<数字>.out。
var (
	fakeListPattern = regexp.MustCompile(`^data/scan_[0-9]+/batch_[0-9]+_targets\.txt$`)
	fakeOutPattern  = regexp.MustCompile(`^data/scan_[0-9]+/batch_[0-9]+\.out$`)
)

func init() {
	if os.Getenv(fakePathGuardEnv) != "1" {
		return
	}
	os.Exit(fakePathGuardMain(os.Args[1:]))
}

// fakePathGuardMain 是哨兵入口：成功时向 stdout 打印规范化后的绝对路径。
func fakePathGuardMain(args []string) int {
	if len(args) != 2 {
		fmt.Printf("路径哨兵需要 2 个参数（flag 与取值），实际 %d 个", len(args))
		return fakePathGuardCode
	}
	root := os.Getenv(fakePathGuardRootEnv)
	if root == "" {
		fmt.Print("路径哨兵缺少临时根目录环境变量")
		return fakePathGuardCode
	}
	resolved, err := resolveFakeArtifact(root, args[0], args[1])
	if err != nil {
		fmt.Print(err.Error())
		return fakePathGuardCode
	}
	fmt.Print(resolved)
	return 0
}

// resolveFakeArtifact 把 flag 的取值规范化成绝对路径，并证明它严格位于 root 之内：
//   - 拒绝空值、绝对路径、反斜杠与 NUL；
//   - 拒绝空片段、`.`、`..` 等无法安全规范化的片段；
//   - 只接受 data/scan_<数字>/batch_<数字>_{targets.txt|out} 形态；
//   - 逐段检查符号链接，任何一段是链接都拒绝（防符号链接逃逸）；
//   - 最后用 EvalSymlinks 解析已存在的父目录，复查真实路径仍在 root 内。
func resolveFakeArtifact(root, flag, value string) (string, error) {
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("临时根目录必须是绝对路径: %q", root)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("临时根目录不可解析 %q: %v", root, err)
	}
	if value == "" {
		return "", fmt.Errorf("%s 缺值", flag)
	}
	if filepath.IsAbs(value) {
		return "", fmt.Errorf("%s 不允许绝对路径: %q", flag, value)
	}
	if strings.ContainsAny(value, "\x00\\") {
		return "", fmt.Errorf("%s 取值包含非法字符: %q", flag, value)
	}
	var pattern *regexp.Regexp
	switch flag {
	case "-list":
		pattern = fakeListPattern
	case "-o":
		pattern = fakeOutPattern
	default:
		return "", fmt.Errorf("路径哨兵只支持 -list 与 -o，收到 %q", flag)
	}
	segments := strings.Split(value, "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return "", fmt.Errorf("%s 路径不可安全规范化（出现空片段、. 或 ..）: %q", flag, value)
		}
	}
	if !pattern.MatchString(value) {
		return "", fmt.Errorf("%s 路径形态不受控（只允许 data/scan_<id>/batch_<id> 产物）: %q", flag, value)
	}
	lexical := filepath.Join(append([]string{realRoot}, segments...)...)
	if !withinRoot(realRoot, lexical) {
		return "", fmt.Errorf("%s 越出临时根目录: %q（解析为 %q）", flag, value, lexical)
	}
	current := realRoot
	for index, segment := range segments {
		current = filepath.Join(current, segment)
		info, statErr := os.Lstat(current)
		if statErr != nil {
			if !errors.Is(statErr, os.ErrNotExist) {
				return "", fmt.Errorf("%s 无法检查 %q: %v", flag, current, statErr)
			}
			if index != len(segments)-1 {
				return "", fmt.Errorf("%s 上级目录不存在: %q", flag, current)
			}
			// 输出文件允许尚不存在。
			break
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%s 路径片段是符号链接（可能是越界逃逸）: %q", flag, current)
		}
		if index == len(segments)-1 && flag == "-list" && !info.Mode().IsRegular() {
			return "", fmt.Errorf("-list 目标不是普通文件: %q", current)
		}
	}
	realDir, dirErr := filepath.EvalSymlinks(filepath.Dir(lexical))
	if dirErr != nil {
		return "", fmt.Errorf("%s 目录不可解析 %q: %v", flag, filepath.Dir(lexical), dirErr)
	}
	resolved := filepath.Join(realDir, filepath.Base(lexical))
	if !withinRoot(realRoot, resolved) {
		return "", fmt.Errorf("%s 真实路径越出临时根目录: %q", flag, resolved)
	}
	return resolved, nil
}

// withinRoot 判断 path 是否严格位于 root 之内（root 自身不算批次产物）。
func withinRoot(root, path string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	if path == root {
		return true
	}
	return strings.HasPrefix(path, root+string(os.PathSeparator))
}
