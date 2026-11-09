//go:build race

package scanner

// raceDetectorEnabled 表示当前测试二进制由 -race 构建。
//
// -race 会给解析与 SQLite 写路径加上大量插桩：同样的 50 万行写库，
// 单次写事务可能超过 store 的 busy_timeout(5s) 而偶发 SQLITE_BUSY。
// 因此 race 档按比例降档（仍是同一条流式链路），50 万行的完整断言由容量档保证。
const raceDetectorEnabled = true
