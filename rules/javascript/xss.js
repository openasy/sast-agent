function show(el, name) {
  // ruleid: openasy.javascript.html-from-data
  el.innerHTML = "<b>" + name + "</b>";
  // ruleid: openasy.javascript.html-from-data
  document.write(location.hash);
  // ok: openasy.javascript.html-from-data
  el.textContent = name;
  // ok: openasy.javascript.html-from-data
  el.innerHTML = "";
}
