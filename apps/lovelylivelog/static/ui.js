// Small helpers shared by the page modules.
export const $ = id => document.getElementById(id);

let toastTimer = null;
export function toast(text, tone = '') {
  const node = $('toast');
  if (!node) return;
  node.textContent = text;
  node.className = `toast visible${tone ? ' ' + tone : ''}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { node.className = 'toast'; }, 2200);
}

export async function copyText(text, label = '已复制') {
  try {
    await navigator.clipboard.writeText(text);
    toast(label);
    return true;
  } catch {
    toast('复制失败，请手动选择文字复制', 'error');
    return false;
  }
}

// Read-only dialogs close when the backdrop is clicked; form dialogs keep their input.
document.addEventListener('click', event => {
  const target = event.target;
  if (!(target instanceof HTMLDialogElement) || !target.open || !target.hasAttribute('data-light-dismiss')) return;
  // Clicks on the dialog's own padding also target the dialog; only close outside its box.
  const box = target.getBoundingClientRect();
  if (event.clientX < box.left || event.clientX > box.right || event.clientY < box.top || event.clientY > box.bottom) target.close();
});
