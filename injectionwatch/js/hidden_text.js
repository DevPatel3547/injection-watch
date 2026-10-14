/*
 * InjectionWatch shared rendered-DOM extractor.
 * Used by (1) the Python rendered pass via Playwright page.evaluate and
 *         (2) the browser extension content script.
 * Uses computed styles + layout boxes, so it sees external stylesheets and JS-inserted
 * content that the static Python extractor cannot.
 * Hiding signals (computed style): display:none, visibility, opacity, zero font, content-visibility,
 * clip / clip-path, scale(0) transforms, transparent text colour, zero-size boxes with clipped
 * overflow, off-screen boxes, negative text-indent, and text colour matching the background.
 * Returns {candidates: [{text, location, techniques, path, in_code}]}. Never sends anything anywhere.
 */
function injectionwatchHiddenText(doc) {
  var win = doc.defaultView || window;
  var SKIP = { SCRIPT: 1, STYLE: 1, SVG: 1, IFRAME: 1, OBJECT: 1, CANVAS: 1, HEAD: 1 };
  var NONRENDER = { NOSCRIPT: 1, TEMPLATE: 1 };
  var BLOCK = /^(P|DIV|LI|TD|TH|H[1-6]|SECTION|ARTICLE|HEADER|FOOTER|NAV|ASIDE|MAIN|BLOCKQUOTE|PRE|FIGCAPTION|DD|DT|FORM|BODY|TABLE|UL|OL|ADDRESS|DETAILS|SUMMARY)$/;
  var CODE = { CODE: 1, PRE: 1, KBD: 1, SAMP: 1, BLOCKQUOTE: 1, Q: 1 };
  var memo = new Map();

  function rgb(s) {
    var m = /rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([\d.]+))?\)/.exec(s || "");
    if (!m) return null;
    if (m[4] !== undefined && parseFloat(m[4]) === 0) return null;
    return [+m[1], +m[2], +m[3]];
  }
  // alpha channel of a computed colour string; 1 when opaque or unparseable
  function alpha(s) {
    if (!s) return 1;
    if (s === "transparent") return 0;
    var m = /rgba\(\s*[\d.]+,\s*[\d.]+,\s*[\d.]+,\s*([\d.]+)\s*\)/.exec(s);
    return m ? parseFloat(m[1]) : 1;
  }
  function effectiveBg(el) {
    for (var e = el; e && e.nodeType === 1; e = e.parentElement) {
      var c = rgb(win.getComputedStyle(e).backgroundColor);
      if (c) return c;
    }
    return [255, 255, 255];
  }
  function pathOf(el) {
    var s = el.tagName.toLowerCase();
    if (el.id) s += "#" + el.id;
    if (el.classList && el.classList.length) s += "." + Array.prototype.slice.call(el.classList, 0, 2).join(".");
    return s;
  }
  // Returns {loc, tech, root} for an element (inherited hiding is resolved by walking up).
  function state(el) {
    if (memo.has(el)) return memo.get(el);
    var res = null;
    var parent = el.parentElement;
    var ps = parent && parent !== doc.documentElement ? state(parent) : null;
    if (ps && ps.loc !== "visible") {
      res = ps;
    } else {
      var cs = win.getComputedStyle(el);
      var tech = null;
      if (cs.display === "none") tech = "display:none";
      else if (cs.visibility === "hidden" || cs.visibility === "collapse") tech = "visibility:hidden";
      else if (parseFloat(cs.opacity) <= 0.01) tech = "opacity:0";
      else if (parseFloat(cs.fontSize) < 2) tech = "zero_font";
      else if (cs.contentVisibility === "hidden") tech = "content-visibility:hidden";
      else if (/rect\(0/.test(cs.clip) || /inset\((?:50|100)%|circle\(0(?:px|%)?\s*[a)]/.test(cs.clipPath)) tech = "clip";
      else if (/^matrix\(0, 0, 0, 0,/.test(cs.transform) || /scale\(0\)/.test(cs.transform)) tech = "zero_size";
      else if (alpha(cs.color) === 0 || alpha(cs.webkitTextFillColor) === 0) tech = "transparent_text";
      else {
        var r = el.getBoundingClientRect();
        var docW = Math.max(doc.documentElement.scrollWidth, win.innerWidth || 0);
        var clipsOverflow = /hidden|clip/.test(cs.overflow) || /hidden|clip/.test(cs.overflowX) || /hidden|clip/.test(cs.overflowY);
        if ((r.width < 2 || r.height < 2) && clipsOverflow) tech = "zero_size";
        else if (r.right <= 0 || r.bottom <= 0 || r.left >= docW + 50) tech = "offscreen";
        else if (parseFloat(cs.textIndent) <= -500) tech = "offscreen";
      }
      if (tech) res = { loc: "hidden_css", tech: tech, root: el };
      else if ((el.getAttribute("aria-hidden") || "").toLowerCase() === "true") res = { loc: "aria_hidden", tech: "aria-hidden", root: el };
      else res = { loc: "visible", tech: null, root: null };
    }
    memo.set(el, res);
    return res;
  }
  function colorMatch(el) {
    var fg = rgb(win.getComputedStyle(el).color);
    if (!fg) return false;
    var bg = effectiveBg(el);
    var d = Math.sqrt(Math.pow(fg[0] - bg[0], 2) + Math.pow(fg[1] - bg[1], 2) + Math.pow(fg[2] - bg[2], 2));
    return d < 40;
  }
  function nearestBlock(el) {
    for (var e = el; e; e = e.parentElement) if (BLOCK.test(e.tagName)) return e;
    return doc.body;
  }
  function inCode(el) {
    for (var e = el; e; e = e.parentElement) if (CODE[e.tagName]) return true;
    return false;
  }

  var groups = new Map();
  var order = [];
  function add(key, text, loc, tech, path, code) {
    if (!groups.has(key)) { groups.set(key, { parts: [], loc: loc, tech: tech, path: path, code: code }); order.push(key); }
    else { var g0 = groups.get(key); g0.code = g0.code && code; } // "code" only if every part is code
    groups.get(key).parts.push(text);
  }

  var walker = doc.createTreeWalker(doc.body || doc.documentElement, 4 /* SHOW_TEXT */, null);
  var n;
  while ((n = walker.nextNode())) {
    var t = n.nodeValue;
    if (!t || !t.trim()) continue;
    var el = n.parentElement;
    if (!el) continue;
    var skip = false, nonr = null;
    for (var e = el; e; e = e.parentElement) {
      if (SKIP[e.tagName]) { skip = true; break; }
      if (NONRENDER[e.tagName]) nonr = e;
    }
    if (skip) continue;
    if (nonr) { add(nonr, t, "non_rendered", nonr.tagName.toLowerCase(), pathOf(nonr), false); continue; }
    var st = state(el);
    if (st.loc !== "visible") { add(st.root, t, st.loc, st.tech, pathOf(st.root), inCode(el)); continue; }
    var blk = nearestBlock(el);
    var code = inCode(el);
    if (colorMatch(el)) { add("cm:" + pathOf(blk) + ">" + pathOf(el), t, "hidden_css", "color_match", pathOf(el), code); continue; }
    add(blk, t, "visible", null, pathOf(blk), code);
  }
  // <template> content lives in a separate DocumentFragment
  var tpls = doc.querySelectorAll("template");
  for (var i = 0; i < tpls.length; i++) {
    var txt = tpls[i].content ? tpls[i].content.textContent : "";
    if (txt && txt.trim()) add(tpls[i], txt, "non_rendered", "template", pathOf(tpls[i]), false);
  }

  var out = [];
  for (var j = 0; j < order.length; j++) {
    var g = groups.get(order[j]);
    var text = g.parts.map(function (p) { return p.trim(); }).filter(Boolean).join(" ");
    if (!text) continue;
    out.push({ text: text, location: g.loc, techniques: g.tech ? [g.tech] : [], path: g.path, in_code: g.code });
  }
  return { candidates: out };
}
if (typeof module !== "undefined" && module.exports) { module.exports = { injectionwatchHiddenText: injectionwatchHiddenText }; }
