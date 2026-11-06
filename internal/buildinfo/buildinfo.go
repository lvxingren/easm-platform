// Package buildinfo 承载构建期注入的版本信息。
//
// 发布构建通过 ldflags 注入版本号：
//
//	go build -ldflags "-X easm-platform/internal/buildinfo.Version=v1.0.0" .
//
// 未注入时保持默认值 "dev"，便于区分开发构建与正式发布。
package buildinfo

// Version 是当前二进制版本号，由构建/打包脚本（deploy/ubuntu/package.sh）通过 ldflags 注入。
var Version = "dev"
