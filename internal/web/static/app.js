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

// 改密弹窗
function pwModal() { const m = document.getElementById('pw-modal'); if (m) m.style.display = 'flex'; }
function pwClose() { const m = document.getElementById('pw-modal'); if (m) m.style.display = 'none'; }
async function pwSubmit() {
  const oldp = document.getElementById('pw-old').value;
  const newp = document.getElementById('pw-new').value;
  if (newp.length < 6) { toast('新密码至少 6 位', 'err'); return; }
  const res = await postForm('/api/account/password', { old_password: oldp, new_password: newp });
  if (res.ok) { toast('密码已修改', 'ok'); pwClose(); }
  else { toast(res.json.error || '修改失败', 'err'); }
}
