// 全局前端助手：Toast 通知、改密弹窗、fetch 封装（替代原生 alert）
function toast(msg, type) {
  const box = document.getElementById('toasts');
  if (!box) return;
  const el = document.createElement('div');
  el.className = 'toast ' + (type || 'ok');
  el.textContent = msg;
  box.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transform = 'translateX(20px)'; el.style.transition = '.3s'; }, 3400);
  setTimeout(() => el.remove(), 3800);
}

// POST 表单/对象，返回 {ok, status, json}
async function postForm(url, src) {
  let body;
  if (src instanceof FormData) body = src;
  else if (src && src.tagName) body = new FormData(src);
  else { body = new FormData(); if (src) for (const k in src) body.append(k, src[k]); }
  const r = await fetch(url, { method: 'POST', body });
  let j = {}; try { j = await r.json(); } catch (e) {}
  return { ok: r.ok, status: r.status, json: j };
}

// 无 body 的 POST/DELETE
async function postEmpty(url, method) {
  const r = await fetch(url, { method: method || 'POST' });
  let j = {}; try { j = await r.json(); } catch (e) {}
  return { ok: r.ok, status: r.status, json: j };
}

// 轮询后台启动状态：启动 API 立即返回 preparing + request_id，naabu 自检 / 目标解析 /
// 容量预检在后台完成，最终错误（含可操作建议）只能按该请求编号拿到。
// onDone(scanID) 表示启动成功；onError(error, advice, scanID) 表示启动失败或状态不可知。
// 约束：没有 request_id、编号未知（404）、状态已过期（410）、编号不匹配，一律按失败处理，
// 绝不把“查不到状态”误报为启动成功。
async function pollRunStatus(url, requestID, onDone, onError) {
  if (!requestID) {
    onError('启动接口未返回 request_id，无法跟踪本次启动结果，请到执行记录查看', [], 0);
    return;
  }
  const target = url + (url.indexOf('?') >= 0 ? '&' : '?') + 'request_id=' + encodeURIComponent(requestID);
  const deadline = Date.now() + 10 * 60 * 1000;
  while (Date.now() < deadline) {
    let r, j = {};
    try { r = await fetch(target, { cache: 'no-store' }); j = await r.json(); } catch (e) {
      await new Promise(res => setTimeout(res, 1200));
      continue;
    }
    if (!r.ok) {
      // 404 未知编号 / 410 已过期：明确失败，不重试、不表示成功。
      const message = j.error || (r.status === 404 || r.status === 410
        ? '启动请求编号未知或已过期，请到执行记录确认本次结果'
        : '读取启动状态失败');
      onError(message, j.advice || [], j.scan_id || 0);
      return;
    }
    if (j.request_id && j.request_id !== requestID) {
      onError('启动状态与请求编号不匹配，请到执行记录确认本次结果', [], 0);
      return;
    }
    if (j.done) {
      if (j.error) onError(j.error, j.advice || [], j.scan_id || 0);
      else onDone(j.scan_id || 0);
      return;
    }
    await new Promise(res => setTimeout(res, 800));
  }
  onError('等待启动结果超时，请到执行记录查看本次请求的结果', [], 0);
}

// 深浅主题切换：写入 <html data-theme> 并持久化到 localStorage
function toggleTheme() {
  const root = document.documentElement;
  const next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  root.setAttribute('data-theme', next);
  try { localStorage.setItem('easm-theme', next); } catch (e) {}
}

// 移动端/窄屏侧边导航抽屉开关（force 为布尔时强制展开/收起）
function toggleSidebar(force) {
  const sb = document.getElementById('sidebar');
  if (!sb) return;
  const mask = document.getElementById('sidebar-mask');
  const open = (force === undefined) ? !sb.classList.contains('open') : !!force;
  sb.classList.toggle('open', open);
  if (mask) mask.style.display = open ? 'block' : 'none';
}

// 侧边可折叠分组（安全运营）开关，状态记忆到本地；当前页在组内时强制展开。
function toggleNavGroup(id) {
  const sec = document.getElementById(id);
  if (!sec) return;
  const collapsed = sec.classList.toggle('collapsed');
  const btn = sec.querySelector('.nav-sec-toggle');
  if (btn) btn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
  try { localStorage.setItem('easm-nav-' + id, collapsed ? '0' : '1'); } catch (e) {}
}
(function () {
  const sec = document.getElementById('sec-ops');
  if (!sec) return;
  let collapsed = false;
  try { collapsed = localStorage.getItem('easm-nav-sec-ops') === '0'; } catch (e) {}
  if (sec.querySelector('.nav-sec-body .nav-item.active')) collapsed = false;
  sec.classList.toggle('collapsed', collapsed);
  const btn = sec.querySelector('.nav-sec-toggle');
  if (btn) btn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
})();

// 通用模态：显示/隐藏 .modal-mask 容器（复用改密弹窗样式）
function openModal(id) { const m = document.getElementById(id); if (m) m.style.display = 'flex'; }
function closeModal(id) { const m = document.getElementById(id); if (m) m.style.display = 'none'; }
// 点击遮罩空白处关闭（onclick="modalBackdrop(event,'id')"）
function modalBackdrop(ev, id) { if (ev.target === ev.currentTarget) closeModal(id); }

// 批量选择辅助：全选/反选与收集选中值
function toggleAllChecks(master, cls) {
  document.querySelectorAll('.' + cls).forEach(c => { c.checked = master.checked; });
}
function checkedValues(cls) {
  return Array.from(document.querySelectorAll('.' + cls + ':checked')).map(c => c.value);
}

// 改密弹窗（复用通用模态开关，避免重复逻辑）
function pwModal() { openModal('pw-modal'); }
function pwClose() { closeModal('pw-modal'); }
async function pwSubmit() {
  const oldp = document.getElementById('pw-old').value;
  const newp = document.getElementById('pw-new').value;
  if (newp.length < 6) { toast('新密码至少 6 位', 'err'); return; }
  const res = await postForm('/api/account/password', { old_password: oldp, new_password: newp });
  if (res.ok) { toast('密码已修改', 'ok'); pwClose(); }
  else { toast(res.json.error || '修改失败', 'err'); }
}
