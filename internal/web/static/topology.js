// 轻量交互式网络拓扑渲染（原生 SVG，无外部依赖，离线可用，随双主题着色）。
// renderTopology(el, nodes, edges)：nodes=[{ip,role,note}]，edges=[{src,dst,port,proto,risk,note}]
function renderTopology(el, nodes, edges) {
  if (!el) return;
  el.innerHTML = '';
  nodes = (nodes || []).filter(function (n) { return n && n.ip; });
  edges = (edges || []).filter(function (e) { return e && e.src && e.dst; });
  if (!nodes.length) {
    el.innerHTML = '<div class="empty"><div class="big">无拓扑数据</div>解析出的通信关系不足以绘制拓扑</div>';
    return;
  }
  var NS = 'http://www.w3.org/2000/svg';
  var W = Math.max(640, el.clientWidth || 820), H = 500;
  var cx = W / 2, cy = H / 2, R = Math.min(W, H) / 2 - 80;
  var svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
  svg.setAttribute('width', '100%');
  svg.setAttribute('height', H);
  svg.style.maxWidth = '100%';

  var pos = {};
  nodes.forEach(function (n, i) {
    var a = (2 * Math.PI * i) / nodes.length - Math.PI / 2;
    pos[n.ip] = { x: cx + R * Math.cos(a), y: cy + R * Math.sin(a) };
  });

  var riskColor = { high: '#e0483d', mid: '#cf8211', low: '#9aa7ba' };
  var roleColor = { '外部': '#e0483d', '中转': '#cf8211', '跳板': '#cf8211', '服务器': '#2f6bff', '终端': '#12a06a' };
  var lineEls = [];

  edges.forEach(function (e) {
    var s = pos[e.src], d = pos[e.dst];
    if (!s || !d) return;
    var line = document.createElementNS(NS, 'line');
    line.setAttribute('x1', s.x); line.setAttribute('y1', s.y);
    line.setAttribute('x2', d.x); line.setAttribute('y2', d.y);
    line.setAttribute('stroke', riskColor[e.risk] || riskColor.low);
    line.setAttribute('stroke-width', e.risk === 'high' ? 2.4 : 1.2);
    line.setAttribute('stroke-opacity', '0.55');
    var t = document.createElementNS(NS, 'title');
    t.textContent = e.src + ' → ' + e.dst + ':' + (e.port || '') + '/' + (e.proto || '') + (e.note ? (' · ' + e.note) : '');
    line.appendChild(t);
    svg.appendChild(line);
    lineEls.push({ el: line, src: e.src, dst: e.dst });
  });

  nodes.forEach(function (n) {
    var p = pos[n.ip];
    var g = document.createElementNS(NS, 'g');
    g.style.cursor = 'move';
    var c = document.createElementNS(NS, 'circle');
    c.setAttribute('cx', p.x); c.setAttribute('cy', p.y); c.setAttribute('r', 9);
    c.setAttribute('fill', roleColor[n.role] || '#2f6bff');
    c.setAttribute('stroke', 'var(--surface)'); c.setAttribute('stroke-width', '1.5');
    var label = document.createElementNS(NS, 'text');
    label.setAttribute('x', p.x); label.setAttribute('y', p.y - 14);
    label.setAttribute('text-anchor', 'middle');
    label.setAttribute('font-size', '11'); label.setAttribute('fill', 'currentColor');
    label.textContent = n.ip;
    var title = document.createElementNS(NS, 'title');
    title.textContent = n.ip + (n.role ? (' · ' + n.role) : '') + (n.note ? (' · ' + n.note) : '');
    g.appendChild(title); g.appendChild(c); g.appendChild(label);
    svg.appendChild(g);

    var dragging = false;
    function toSvg(ev) {
      var rect = svg.getBoundingClientRect();
      return { x: (ev.clientX - rect.left) * (W / rect.width), y: (ev.clientY - rect.top) * (H / rect.height) };
    }
    g.addEventListener('mousedown', function (ev) { dragging = true; ev.preventDefault(); });
    window.addEventListener('mousemove', function (ev) {
      if (!dragging) return;
      var pt = toSvg(ev);
      p.x = pt.x; p.y = pt.y;
      c.setAttribute('cx', p.x); c.setAttribute('cy', p.y);
      label.setAttribute('x', p.x); label.setAttribute('y', p.y - 14);
      lineEls.forEach(function (le) {
        if (le.src === n.ip) { le.el.setAttribute('x1', p.x); le.el.setAttribute('y1', p.y); }
        if (le.dst === n.ip) { le.el.setAttribute('x2', p.x); le.el.setAttribute('y2', p.y); }
      });
    });
    window.addEventListener('mouseup', function () { dragging = false; });
  });

  el.appendChild(svg);
}
