const shadowRoots = new Map();

const originalAttachShadow = Element.prototype.attachShadow;
Element.prototype.attachShadow = function(init) {
  const root = originalAttachShadow.call(this, { ...init, mode: 'open' });
  shadowRoots.set(this, root);
  return root;
};

function initPanzoom(svg, host) {
  if (svg.dataset.panzoom) return;
  svg.dataset.panzoom = 'true';

  const MIN_SCALE = 0.2, MAX_SCALE = 10;
  let scale = 1, tx = 0, ty = 0;
  let dragging = false, startX = 0, startY = 0;

  function applyTransform() {
    svg.style.transformOrigin = '0 0';
    svg.style.transform = `translate(${tx}px, ${ty}px) scale(${scale})`;
  }

  function clamp() {
    // Host dimensions — the visible container
    const hw = host.clientWidth;
    const hh = host.clientHeight;
    // Scaled SVG dimensions based on its natural (attribute) size
    const sw = svg.width.baseVal.value  * scale;
    const sh = svg.height.baseVal.value * scale;

    // If SVG is smaller than container, lock to 0 (top-left)
    // If SVG is larger than container, allow panning up to the point
    // where the opposite edge aligns with the container edge
    tx = sw < hw ? 0 : Math.min(0, Math.max(tx, hw - sw));
    ty = sh < hh ? 0 : Math.min(0, Math.max(ty, hh - sh));
  }

  svg.addEventListener('wheel', (e) => {
    e.preventDefault();

    const rect = host.getBoundingClientRect();
    // Mouse position relative to the host container
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    const factor = e.deltaMode === 1 ? 0.05 : 0.002;
    const newScale = Math.min(Math.max(scale * (1 - e.deltaY * factor), MIN_SCALE), MAX_SCALE);

    // Zoom toward cursor
    tx = mx - (mx - tx) * (newScale / scale);
    ty = my - (my - ty) * (newScale / scale);
    scale = newScale;

    clamp();
    applyTransform();
  }, { passive: false });

  svg.addEventListener('pointerdown', (e) => {
    dragging = true;
    startX = e.clientX - tx;
    startY = e.clientY - ty;
    svg.setPointerCapture(e.pointerId);
    svg.style.cursor = 'grabbing';
  });

  svg.addEventListener('pointermove', (e) => {
    if (!dragging) return;
    tx = e.clientX - startX;
    ty = e.clientY - startY;
    clamp();
    applyTransform();
  });

  svg.addEventListener('pointerup', () => {
    dragging = false;
    svg.style.cursor = 'grab';
  });

  // The host must clip the SVG — without this the transform bleeds outside
  host.style.overflow = 'hidden';
  host.style.position = 'relative';
  host.style.display = 'block';

  svg.style.cursor = 'grab';

  // Default zoom-in to 150%
  scale = 1;
  clamp();
  applyTransform();
}

const observer = new MutationObserver(() => {
  document.querySelectorAll('.mermaid').forEach(el => {
    const root = shadowRoots.get(el);
    if (!root) return;

    if (!root.querySelector('.custom-injected')) {
      const link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = '/stylesheets/mermaid-custom.css';
      link.classList.add('custom-injected');
      root.appendChild(link);
    }

    root.querySelectorAll('svg:not([data-panzoom]):not(svg svg)').forEach(svg => initPanzoom(svg, el));
  });
});

observer.observe(document.body, { childList: true, subtree: true });
