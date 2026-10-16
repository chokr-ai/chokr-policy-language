(function () {
  'use strict';
  var root = document.documentElement;

  /* Theme toggle */
  var toggle = document.getElementById('theme-toggle');
  if (toggle) {
    toggle.addEventListener('click', function () {
      var next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      localStorage.setItem('theme', next);
    });
  }

  /* Mobile navigation */
  var menu = document.getElementById('menu-btn');
  if (menu) {
    menu.addEventListener('click', function () {
      var open = document.body.classList.toggle('nav-open');
      menu.setAttribute('aria-expanded', String(open));
    });
  }

  /* Code blocks: frame, title, copy button */
  var terminal = /language-(console|sh|bash|shell|powershell)\b/;
  document.querySelectorAll('.prose div.highlighter-rouge').forEach(function (block) {
    var title = block.getAttribute('data-title');
    if (!title && terminal.test(block.className)) title = 'Terminal window';
    var frame = document.createElement('div');
    frame.className = 'code-frame' + (title ? '' : ' no-title');
    var body = document.createElement('div');
    body.className = 'code-body';
    block.parentNode.insertBefore(frame, block);
    body.appendChild(block);
    var button = document.createElement('button');
    button.type = 'button';
    button.className = 'copy';
    button.textContent = 'Copy';
    button.addEventListener('click', function () {
      var text = block.querySelector('pre').innerText.replace(/\n$/, '');
      var done = function () {
        button.textContent = 'Copied';
        setTimeout(function () { button.textContent = 'Copy'; }, 1500);
      };
      if (navigator.clipboard) navigator.clipboard.writeText(text).then(done);
    });
    if (title) {
      var bar = document.createElement('div');
      bar.className = 'code-title';
      var label = document.createElement('span');
      label.textContent = title;
      bar.appendChild(label);
      bar.appendChild(button);
      frame.appendChild(bar);
      frame.appendChild(body);
    } else {
      body.appendChild(button);
      frame.appendChild(body);
    }
  });

  /* Callout kinds: a blockquote whose last paragraph is {: .warning} or {: .next} is styled by class. */

  /* Heading anchors and the "On this page" outline */
  var headings = Array.prototype.filter.call(
    document.querySelectorAll('.prose h2[id], .prose h3[id]'),
    function (h) { return !h.closest('.card'); }
  );
  var toc = document.getElementById('toc');
  if (toc && headings.length > 1) {
    var title = document.createElement('h2');
    title.textContent = 'On this page';
    var list = document.createElement('ul');
    headings.forEach(function (h) {
      var anchor = document.createElement('a');
      anchor.className = 'anchor';
      anchor.href = '#' + h.id;
      anchor.setAttribute('aria-label', 'Link to this section');
      anchor.textContent = '#';
      h.appendChild(anchor);
      var li = document.createElement('li');
      li.className = h.tagName === 'H3' ? 'l3' : 'l2';
      var a = document.createElement('a');
      a.href = '#' + h.id;
      a.textContent = h.childNodes[0].textContent;
      li.appendChild(a);
      list.appendChild(li);
    });
    toc.appendChild(title);
    toc.appendChild(list);
    var links = toc.querySelectorAll('a');
    var spy = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        links.forEach(function (l) { l.classList.toggle('active', l.getAttribute('href') === '#' + entry.target.id); });
      });
    }, { rootMargin: '-10% 0px -80% 0px' });
    headings.forEach(function (h) { spy.observe(h); });
  }

  /* Keep the current sidebar link visible */
  var current = document.querySelector('.sidebar [aria-current="page"]');
  if (current) current.scrollIntoView({ block: 'center' });

  /* Search */
  var modal = document.getElementById('search-modal');
  var input = document.getElementById('search-input');
  var results = document.getElementById('search-results');
  var index = null;
  var selected = -1;

  function load() {
    if (index) return Promise.resolve(index);
    var url = document.currentScript ? document.currentScript.getAttribute('data-search') : null;
    url = url || document.querySelector('script[data-search]').getAttribute('data-search');
    return fetch(url).then(function (r) { return r.json(); }).then(function (data) { index = data; return data; });
  }
  function openSearch() {
    modal.hidden = false;
    input.value = '';
    results.innerHTML = '';
    input.focus();
    load();
  }
  function closeSearch() { modal.hidden = true; }
  function snippet(text, terms) {
    var lower = text.toLowerCase();
    var at = -1;
    terms.some(function (t) { at = lower.indexOf(t); return at >= 0; });
    var start = Math.max(0, at - 40);
    return (start > 0 ? '…' : '') + text.slice(start, start + 110) + '…';
  }
  function render(query) {
    var terms = query.toLowerCase().split(/\s+/).filter(Boolean);
    results.innerHTML = '';
    selected = -1;
    if (!terms.length || !index) return;
    var scored = index.map(function (p) {
      var title = p.title.toLowerCase();
      var text = p.text.toLowerCase();
      var score = 0;
      for (var i = 0; i < terms.length; i++) {
        var t = terms[i];
        if (title.indexOf(t) >= 0) score += 10;
        if (text.indexOf(t) >= 0) score += 1; else return { p: p, score: 0 };
      }
      return { p: p, score: score };
    }).filter(function (s) { return s.score > 0; }).sort(function (a, b) { return b.score - a.score; }).slice(0, 8);
    if (!scored.length) {
      var empty = document.createElement('li');
      empty.className = 'search-empty';
      empty.textContent = 'No results.';
      results.appendChild(empty);
      return;
    }
    scored.forEach(function (s) {
      var li = document.createElement('li');
      var a = document.createElement('a');
      a.href = s.p.url;
      var strong = document.createElement('strong');
      strong.textContent = s.p.title;
      var span = document.createElement('span');
      span.textContent = snippet(s.p.text, terms);
      a.appendChild(strong);
      a.appendChild(span);
      li.appendChild(a);
      results.appendChild(li);
    });
  }
  if (modal) {
    document.getElementById('search-open').addEventListener('click', openSearch);
    modal.querySelector('[data-close]').addEventListener('click', closeSearch);
    input.addEventListener('input', function () { load().then(function () { render(input.value); }); });
    input.addEventListener('keydown', function (e) {
      var items = results.querySelectorAll('a');
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        if (!items.length) return;
        selected = (selected + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length;
        items.forEach(function (a, i) { a.classList.toggle('sel', i === selected); });
      } else if (e.key === 'Enter' && items.length) {
        items[Math.max(selected, 0)].click();
      }
    });
    document.addEventListener('keydown', function (e) {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); openSearch(); }
      else if (e.key === 'Escape' && !modal.hidden) closeSearch();
    });
  }
})();
