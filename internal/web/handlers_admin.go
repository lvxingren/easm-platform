package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"easm-platform/internal/store"
)

// requireWrite 允许 operator/admin，拒绝 viewer（只读账号）
func (s *Server) requireWrite(next http.HandlerFunc) http.HandlerFunc {
	return s.auth(func(w http.ResponseWriter, r *http.Request) {
		if currentUser(r).role == "viewer" {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				writeJSON(w, 403, map[string]string{"error": "只读账号无此操作权限"})
				return
			}
			http.Error(w, "只读账号无此操作权限", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

func validRole(role string) bool {
	return role == "admin" || role == "operator" || role == "viewer"
}

func roleName(role string) string {
	switch role {
	case "admin":
		return "管理员"
	case "operator":
		return "操作员"
	case "viewer":
		return "只读"
	}
	return role
}

// ---------- 账号管理页 ----------

func (s *Server) pageAccounts(w http.ResponseWriter, r *http.Request) {
	bd, _ := s.baseData(r, "账号管理", "accounts")
	users, _ := s.st.Users()
	s.render(w, "accounts.html", struct {
		pageData
		Users []store.User
	}{bd, users})
}

func (s *Server) pageAudit(w http.ResponseWriter, r *http.Request) {
	bd, _ := s.baseData(r, "操作审计", "audit")
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	username := strings.TrimSpace(r.URL.Query().Get("user"))
	logs, err := s.st.AuditLogsFiltered(query, username, 2000)
	if err != nil {
		http.Error(w, "读取审计流水失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, "audit.html", struct {
		pageData
		Logs  []store.AuditLog
		Query string
		User  string
	}{bd, logs, query, username})
}

// ---------- 账号 API ----------

func (s *Server) apiCreateUser(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	role := r.FormValue("role")
	display := strings.TrimSpace(r.FormValue("display_name"))
	if username == "" || len(password) < 6 {
		writeJSON(w, 400, map[string]string{"error": "用户名不能为空，密码至少 6 位"})
		return
	}
	if !validRole(role) {
		writeJSON(w, 400, map[string]string{"error": "角色非法（admin/operator/viewer）"})
		return
	}
	if u, _ := s.st.UserByName(username); u != nil {
		writeJSON(w, 400, map[string]string{"error": "用户名已存在"})
		return
	}
	id, err := s.st.CreateUser(username, password, role, display)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "创建账号", username, "role="+role)
	writeJSON(w, 200, map[string]interface{}{"id": id})
}

func (s *Server) apiUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	role := r.FormValue("role")
	display := strings.TrimSpace(r.FormValue("display_name"))
	enabled := r.FormValue("enabled") == "on"
	if !validRole(role) {
		writeJSON(w, 400, map[string]string{"error": "角色非法"})
		return
	}
	users, _ := s.st.Users()
	var target *store.User
	for i := range users {
		if users[i].ID == id {
			target = &users[i]
			break
		}
	}
	if target == nil {
		writeJSON(w, 404, map[string]string{"error": "账号不存在"})
		return
	}
	if target.Role == "admin" && target.Enabled && (!enabled || role != "admin") {
		if admins, _ := s.st.CountEnabledAdmins(); admins <= 1 {
			writeJSON(w, 400, map[string]string{"error": "不能降级或停用最后一个管理员"})
			return
		}
	}
	if err := s.st.UpdateUser(id, role, display, enabled); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "修改账号", target.Username, fmt.Sprintf("role=%s enabled=%v", role, enabled))
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

func (s *Server) apiResetPassword(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if len(r.FormValue("password")) < 6 {
		writeJSON(w, 400, map[string]string{"error": "密码至少 6 位"})
		return
	}
	if err := s.st.SetUserPassword(id, r.FormValue("password")); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "重置账号密码", "#"+r.PathValue("id"), "")
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

func (s *Server) apiDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if id == currentUser(r).userID {
		writeJSON(w, 400, map[string]string{"error": "不能删除当前登录账号"})
		return
	}
	users, _ := s.st.Users()
	for _, u := range users {
		if u.ID == id && u.Role == "admin" && u.Enabled {
			if admins, _ := s.st.CountEnabledAdmins(); admins <= 1 {
				writeJSON(w, 400, map[string]string{"error": "不能删除最后一个管理员"})
				return
			}
		}
	}
	if err := s.st.DeleteUser(id); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "删除账号", "#"+r.PathValue("id"), "")
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

// apiChangeOwnPassword 任意登录用户修改自己的密码（需校验原密码）
func (s *Server) apiChangeOwnPassword(w http.ResponseWriter, r *http.Request) {
	sess := currentUser(r)
	if len(r.FormValue("new_password")) < 6 {
		writeJSON(w, 400, map[string]string{"error": "新密码至少 6 位"})
		return
	}
	if _, err := s.st.Authenticate(sess.username, r.FormValue("old_password")); err != nil {
		writeJSON(w, 400, map[string]string{"error": "原密码错误"})
		return
	}
	if err := s.st.SetUserPassword(sess.userID, r.FormValue("new_password")); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "修改本人密码", sess.username, "")
	writeJSON(w, 200, map[string]string{"ok": "1"})
}
