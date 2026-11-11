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
  // 安全运营与系统管理两个分组共用折叠逻辑；当前页在组内时强制展开。
  ['sec-ops', 'sec-admin'].forEach(function (id) {
    const sec = document.getElementById(id);
    if (!sec) return;
    let collapsed = false;
    try { collapsed = localStorage.getItem('easm-nav-' + id) === '0'; } catch (e) {}
    if (sec.querySelector('.nav-sec-body .nav-item.active')) collapsed = false;
    sec.classList.toggle('collapsed', collapsed);
    const btn = sec.querySelector('.nav-sec-toggle');
    if (btn) btn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
  });
})();

// 通用模态：显示/隐藏 .modal-mask 容器（复用改密弹窗样式）
function openModal(id) { const m = document.getElementById(id); if (m) m.style.display = 'flex'; }
function closeModal(id) { const m = document.getElementById(id); if (m) m.style.display = 'none'; }
// 点击遮罩空白处关闭（onclick="modalBackdrop(event,'id')"）
function modalBackdrop(ev, id) { if (ev.target === ev.currentTarget) closeModal(id); }

// ---------- 应用内确认 / 输入弹窗（替代浏览器原生 confirm / prompt） ----------
// 原生弹窗在 Chrome 中会显示成「127.0.0.1:8443 显示」，样式无法与平台统一，
// 部分内嵌环境还会直接拦截；这里复用 .modal 结构动态渲染，返回 Promise。
// 返回值：appFormDialog 确认为字段对象、取消为 null；appConfirm 为布尔；appPrompt 为字符串或 null。
function appFormDialog(options) {
  const opt = Object.assign({
    title: '请确认', message: '', okText: '确定', cancelText: '取消', danger: false, fields: []
  }, options || {});
  return new Promise(resolve => {
    const mask = document.createElement('div');
    mask.className = 'modal-mask';
    mask.dataset.appDialog = '1';
    mask.style.display = 'flex';

    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');

    const head = document.createElement('div');
    head.className = 'modal-head';
    const title = document.createElement('h3');
    title.textContent = opt.title;
    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'modal-close';
    close.setAttribute('aria-label', '关闭');
    close.textContent = '×';
    head.append(title, close);

    const body = document.createElement('div');
    body.className = 'modal-body';
    const stack = document.createElement('div');
    stack.className = 'stack';
    if (opt.message) {
      const msg = document.createElement('p');
      msg.className = 'hint';
      msg.style.margin = '0';
      msg.style.whiteSpace = 'pre-line';
      msg.textContent = opt.message;
      stack.appendChild(msg);
    }
    const controls = {};
    (opt.fields || []).forEach(field => {
      const label = document.createElement('label');
      label.className = 'field';
      const caption = document.createElement('span');
      caption.textContent = field.label || '';
      const input = field.multiline ? document.createElement('textarea') : document.createElement('input');
      if (field.multiline) input.rows = field.rows || 3;
      else input.type = field.type || 'text';
      input.value = field.value || '';
      input.placeholder = field.placeholder || '';
      input.autocomplete = field.autocomplete || 'off';
      label.append(caption, input);
      if (field.help) {
        const help = document.createElement('span');
        help.className = 'field-help';
        help.textContent = field.help;
        label.appendChild(help);
      }
      if (field.name) controls[field.name] = input;
      stack.appendChild(label);
    });
    const error = document.createElement('p');
    error.className = 'field-help';
    error.style.cssText = 'display:none;color:var(--danger-text);margin:0';
    stack.appendChild(error);
    body.appendChild(stack);

    const foot = document.createElement('div');
    foot.className = 'modal-foot';
    const cancelBtn = document.createElement('button');
    cancelBtn.type = 'button';
    cancelBtn.className = 'btn ghost';
    cancelBtn.textContent = opt.cancelText;
    const okBtn = document.createElement('button');
    okBtn.type = 'button';
    okBtn.className = 'btn ' + (opt.danger ? 'danger' : 'primary');
    okBtn.textContent = opt.okText;
    foot.append(cancelBtn, okBtn);

    modal.append(head, body, foot);
    mask.appendChild(modal);
    document.body.appendChild(mask);

    let done = false;
    const restoreFocus = document.activeElement;
    const finish = value => {
      if (done) return;
      done = true;
      document.removeEventListener('keydown', onKey, true);
      if (mask.parentNode) mask.parentNode.removeChild(mask);
      if (restoreFocus && restoreFocus.focus) { try { restoreFocus.focus(); } catch (e) {} }
      resolve(value);
    };
    const showError = (input, text) => {
      error.textContent = text;
      error.style.display = 'block';
      if (input) input.focus();
    };
    const submit = () => {
      const values = {};
      for (const field of (opt.fields || [])) {
        const input = controls[field.name];
        if (!input) continue;
        const value = input.value.trim();
        values[field.name] = value;
        if (field.required && !value) {
          showError(input, field.label ? field.label.replace(/（.*?）|\(.*?\)/g, '') + '不能为空' : '该项不能为空');
          return;
        }
        if (field.minLength && value.length < field.minLength) {
          showError(input, field.minLengthMessage || ('至少输入 ' + field.minLength + ' 个字符'));
          return;
        }
      }
      finish(values);
    };
    const onKey = ev => {
      if (ev.key === 'Escape') { ev.preventDefault(); ev.stopPropagation(); finish(null); }
    };
    close.addEventListener('click', () => finish(null));
    cancelBtn.addEventListener('click', () => finish(null));
    okBtn.addEventListener('click', submit);
    mask.addEventListener('click', ev => { if (ev.target === mask) finish(null); });
    document.addEventListener('keydown', onKey, true);
    Object.values(controls).forEach(input => {
      input.addEventListener('input', () => { error.style.display = 'none'; });
      input.addEventListener('keydown', ev => {
        if (ev.key === 'Enter' && input.tagName !== 'TEXTAREA') { ev.preventDefault(); submit(); }
      });
    });
    const first = Object.values(controls)[0];
    if (first) { first.focus(); if (first.select && !first.value) first.select(); }
    else okBtn.focus();
  });
}

// 应用内确认框：返回 true（确定）/ false（取消、Esc、点遮罩）。
function appConfirm(message, options) {
  return appFormDialog(Object.assign({ title: '请确认', message: message, okText: '确定' }, options || {})).then(v => v !== null);
}

// 应用内输入框：返回去空格后的字符串，取消返回 null。
function appPrompt(message, options) {
  const opt = Object.assign({
    title: '请输入', label: '', placeholder: '', value: '', required: true, type: 'text', minLength: 0, help: ''
  }, options || {});
  return appFormDialog({
    title: opt.title,
    message: message,
    okText: opt.okText || '确定',
    fields: [{
      name: 'value', label: opt.label, placeholder: opt.placeholder, value: opt.value,
      required: opt.required, type: opt.type, minLength: opt.minLength, help: opt.help,
      minLengthMessage: opt.minLengthMessage, autocomplete: opt.autocomplete
    }]
  }).then(v => v === null ? null : v.value);
}

// 加白弹窗：统一收集必填原因与可选备注，返回 {reason, remark} 或 null。
function appWhitelistDialog(target, options) {
  const opt = Object.assign({ defaultReason: '', defaultRemark: '' }, options || {});
  return appFormDialog({
    title: '加入白名单',
    message: (target ? '将 ' + target + ' 加入白名单。' : '') + '加白原因为必填项，备注可留空。',
    okText: '确认加白',
    fields: [
      { name: 'reason', label: '加白原因（必填）', value: opt.defaultReason, required: true, multiline: true, rows: 2, placeholder: '如：业务官方服务 / 已确认合规 / 工单 #1024' },
      { name: 'remark', label: '备注（可选）', value: opt.defaultRemark, placeholder: '补充说明，可留空' }
    ]
  });
}

// 静态模态统一支持 Esc 关闭；有动态确认框时交给它自己处理，避免连带关闭下层的静态弹窗。
if (document.addEventListener) {
  document.addEventListener('keydown', function (ev) {
    if (ev.key !== 'Escape') return;
    const visible = Array.from(document.querySelectorAll('.modal-mask'))
      .filter(m => m.style.display !== 'none');
    if (visible.some(m => m.dataset && m.dataset.appDialog === '1')) return;
    const masks = visible.filter(m => !(m.dataset && m.dataset.appDialog === '1'));
    if (!masks.length) return;
    masks[masks.length - 1].style.display = 'none';
  });
}

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
