/* app.js — Random Level roulette UI, driven entirely by BufferedWheelPool.
   Reuses the existing markup/CSS in index.html and its global helpers
   ($, qsa, t, escapeHTML, toast, DIFF_OPTIONS, diffOptionLabel, diffOptionIcon). */
import { BufferedWheelPool } from './buffered-wheel-pool.js';

/* ---------- constants / local helpers ---------- */
const CARD_STEP = 248; /* 232px card + 16px gap — keep in sync with .wheel-card CSS */
const DL_STEPS = [0, 1000, 10000, 50000, 100000, 500000, 1000000];
const SPIN_CATS = [['recent','spinCatAll'],['awarded','popRated'],['featured','popFeatured'],['magic','popMagic'],['trending','popTrending']];
const SPIN_LEN = [['','lenAny'],['0','Tiny'],['1','Short'],['2','Medium'],['3','Long'],['4','XL']];
const GD_LENGTH_NAMES = ['Tiny','Short','Medium','Long','XL'];

function fmtNum(n){ n = Number(n||0); if(n>=1e6) return (n/1e6).toFixed(1).replace(/\.0$/,'')+'M'; if(n>=1e3) return (n/1e3).toFixed(1).replace(/\.0$/,'')+'K'; return String(n); }
function lengthLabel(lv){ if(lv==null) return '—'; if(typeof lv.length==='string' && lv.length) return lv.length; return GD_LENGTH_NAMES[Number(lv.length)] || '—'; }
function shuffle(a){ for(let i=a.length-1;i>0;i--){ const j=Math.floor(Math.random()*(i+1)); const tmp=a[i]; a[i]=a[j]; a[j]=tmp; } return a; }
function isRu(){ return typeof lang !== 'undefined' && lang === 'ru'; }
const STR = {
  empty:   () => t('spinPoolEmpty'),
  limited: () => isRu() ? 'Достигнут предел поиска — попробуйте более широкие фильтры' : 'Search range reached — try broader filters',
  error:   () => isRu() ? 'Ошибка запроса — нажмите на колесо, чтобы повторить' : 'Request failed — click the wheel to retry',
  ready:   n  => t('spinPoolCount').replace('{n}', n)
};

/* ---------- 2. FILTERS (single source of truth, committed via debounce) ---------- */
const filters = {
  diffs: new Set(DIFF_OPTIONS.filter(o => o.v).map(o => o.v)),
  cat: 'recent', len: '', minDl: 0, starred: false
};

/* ---------- 1. STATE MANAGEMENT ---------- */
const ui = { built:false, active:false, spinning:false, raf:0, lastTs:0,
             idleOffset:0, idleWidth:0, lastState:null, prevStatus:null,
             lastPoolSize:-1, debounce:0 };

const pool = new BufferedWheelPool({
  targetSize: 80,
  onUpdate: function(state){
    ui.lastState = state;
    if(state.status !== ui.prevStatus){
      if(state.status === 'empty')   toast(STR.empty(),   'error');
      if(state.status === 'limited') toast(STR.limited(), 'error');
      ui.prevStatus = state.status;
    }
    updateStatus(state);
    updateSpinButton();          /* disabled while warming, enabled on canSpin */
    updateEmptyBox(state);
    if(ui.active && !ui.spinning && state.poolSize !== ui.lastPoolSize){
      ui.lastPoolSize = state.poolSize;
      renderIdleStrip();
    }
  }
});

function commitFilters(){
  clearTimeout(ui.debounce);
  ui.debounce = setTimeout(function(){ pool.reset(filters); }, 250);
}

/* ---------- status line / button / empty box ---------- */
function warmingText(s){ return t('spinSearching').replace('{matches}', s.poolSize).replace('{target}', s.targetSize).replace('{pages}', s.pagesScanned); }
function updateStatus(s){
  const el = $('spin-pool-status'); if(!s){ el.textContent = ''; return; }
  if(s.status === 'warming') el.textContent = warmingText(s);
  else if(s.status === 'ready' || s.status === 'settled') el.textContent = STR.ready(s.poolSize);
  else if(s.status === 'empty') el.textContent = STR.empty();
  else if(s.status === 'limited') el.textContent = STR.limited();
  else if(s.status === 'error') el.textContent = STR.error();
}
function updateSpinButton(){
  const btn = $('spin-btn'), s = ui.lastState;
  btn.disabled = ui.spinning || !s || s.status === 'warming' || !s.canSpin;
  btn.textContent = ui.spinning ? t('spinBtnBusy') : t('spinBtn');
}
function updateEmptyBox(s){
  const box = $('wheel-empty');
  if(!s || s.poolSize > 0){ box.hidden = true; box.classList.remove('loading'); return; }
  box.hidden = false;
  box.classList.toggle('loading', s.status === 'warming' || s.status === 'error');
  if(s.status === 'warming') box.textContent = warmingText(s);
  else if(s.status === 'error') box.textContent = STR.error();
  else if(s.status === 'empty') box.textContent = STR.empty();
  else if(s.status === 'limited') box.textContent = STR.limited();
  else box.hidden = true;
}

/* ---------- wheel cards ---------- */
function buildWheelCard(lv){
  const el = document.createElement('div');
  el.className = 'wheel-card'; el.dataset.id = String(lv.id);
  const face = lv.difficultyFace ? 'https://gdbrowser.com/assets/difficulties/'+encodeURIComponent(lv.difficultyFace)+'.png' : '';
  el.innerHTML = '<div class="wheel-card-inner">'
    + '<div class="wc-thumb"><img class="wc-thumb-img" src="https://levelthumbs.prevter.me/thumbnail/'+encodeURIComponent(lv.id)+'/small" alt="" loading="lazy" onerror="this.remove()">'
    + (face ? '<img class="wc-face" src="'+face+'" alt="" loading="lazy">' : '') + '<div class="wc-rarity"></div></div>'
    + '<div class="wc-body"><div class="wc-name">'+escapeHTML(lv.name || ('#'+lv.id))+'</div>'
    + '<div class="wc-creator">by '+escapeHTML(lv.author || '—')+'</div>'
    + '<div class="wc-diff">'+(face ? '<img src="'+face+'" alt="">' : '')+'<span>'+escapeHTML(lv.difficulty || '—')+'</span></div>'
    + '<div class="wc-stats"><span>★ '+(lv.stars||0)+'</span><span>⬇ '+fmtNum(lv.downloads)+'</span><span>♥ '+fmtNum(lv.likes)+'</span></div>'
    + '</div></div>';
  return el;
}
const tx = o => 'translate3d('+(-o)+'px,-50%,0)';

/* ---------- idle strip (gentle drift while waiting) ---------- */
function renderIdleStrip(){
  if(ui.spinning) return;
  const track = $('wheel-track'); track.innerHTML = '';
  ui.idleOffset = 0; ui.idleWidth = 0;
  const levels = ui.lastState ? shuffle(ui.lastState.levels.slice()) : [];
  track.style.transform = tx(0);
  if(levels.length < 2) return;
  const need = Math.ceil((($('wheel-stage').clientWidth || 1040) * 1.5) / CARD_STEP) + 4;
  const loop = []; for(let i = 0; i < need; i++) loop.push(levels[i % levels.length]);
  loop.concat(loop).forEach(lv => track.appendChild(buildWheelCard(lv)));
  ui.idleWidth = loop.length * CARD_STEP;
}
function frame(ts){
  if(!ui.active) return;
  ui.raf = requestAnimationFrame(frame);
  const dt = Math.min(0.05, (ts - (ui.lastTs || ts)) / 1000); ui.lastTs = ts;
  if(!ui.spinning && ui.idleWidth){
    ui.idleOffset = (ui.idleOffset + 26 * dt) % ui.idleWidth;
    $('wheel-track').style.transform = tx(ui.idleOffset);
    $('wheel-parallax').style.transform = 'translate3d('+(Math.sin(ui.idleOffset/900)*26).toFixed(2)+'px,0,0)';
  }
}

/* ---------- 3. THE SPIN — pure animation, NEVER fetches ---------- */
function startSpin(){
  if(ui.spinning) return;
  const plan = pool.spinPlan(20);         /* 19 dummy frames + 1 winner */
  if(!plan) return;
  ui.spinning = true;
  $('spin-filters').classList.add('locked');
  updateSpinButton();

  const track = $('wheel-track'), stage = $('wheel-stage');
  const stageW = stage.clientWidth;
  /* Lead-in padding sampled from the already-buffered pool (no network). */
  const src = ui.lastState.levels;
  const leadCount = Math.ceil(stageW / CARD_STEP) + 2;
  const seq = [];
  for(let i = 0; i < leadCount; i++) seq.push(src[Math.floor(Math.random()*src.length)]);
  seq.push.apply(seq, plan.frames);

  track.innerHTML = '';
  seq.forEach(lv => track.appendChild(buildWheelCard(lv)));
  const winnerIndex = seq.length - 1;
  const centerOf = i => i * CARD_STEP + 116;
  const startOffset = centerOf(Math.floor(leadCount / 2)) - stageW / 2;
  const jitter = (Math.random() * 2 - 1) * 70;   /* land slightly off-center… */
  const endOffset = centerOf(winnerIndex) - stageW / 2 + jitter;
  track.style.transform = tx(startOffset);
  stage.classList.add('wheel-live');

  runSpinTicker();
  const anim = track.animate(
    [{ transform: tx(startOffset) }, { transform: tx(endOffset) }],
    { duration: 6200 + Math.random() * 600, easing: 'cubic-bezier(.1,.7,.1,1)', fill: 'forwards' }
  );
  anim.onfinish = function(){
    /* …then snap-settle onto dead center. */
    const settle = track.animate(
      [{ transform: tx(endOffset) }, { transform: tx(endOffset - jitter) }],
      { duration: 450, easing: 'cubic-bezier(.22,1,.36,1)', fill: 'forwards' }
    );
    settle.onfinish = function(){
      track.style.transform = tx(endOffset - jitter);
      anim.cancel(); settle.cancel();
      stage.classList.remove('wheel-live');
      track.classList.remove('blur');
      const card = track.children[winnerIndex];
      if(card) card.classList.add('wheel-win');
      setTimeout(function(){ if(ui.active) showSpinResult(plan.winner); }, 700);
    };
  };
}
function runSpinTicker(){
  let lastIdx = -1, prevOff = null, prevTs = null;
  (function step(ts){
    if(!ui.spinning) return;
    requestAnimationFrame(step);
    const m = new DOMMatrixReadOnly(getComputedStyle($('wheel-track')).transform);
    const off = -m.m41;
    if(prevOff != null && prevTs != null){
      const v = Math.abs((off - prevOff) / Math.max(0.001, (ts - prevTs) / 1000));
      $('wheel-track').classList.toggle('blur', v > 1500);
    }
    prevOff = off; prevTs = ts;
    const idx = Math.floor(off / CARD_STEP);
    if(idx !== lastIdx){
      lastIdx = idx;
      const mk = $('wheel-marker');
      mk.classList.remove('tick'); void mk.offsetWidth; mk.classList.add('tick');
    }
  })(performance.now());
}

/* ---------- result reveal (reuses .sr-* markup/styles) ---------- */
function showSpinResult(lv){
  const id = String(lv.id);
  const face = lv.difficultyFace ? 'https://gdbrowser.com/assets/difficulties/'+encodeURIComponent(lv.difficultyFace)+'.png' : '';
  $('sr-card').innerHTML = '<div class="sr-hero"><div class="sr-rays"></div>'
    + '<img src="https://levelthumbs.prevter.me/thumbnail/'+encodeURIComponent(id)+'/small" alt="" onerror="this.remove()">'
    + '<div class="sr-eyebrow">'+escapeHTML(t('spinResultEyebrow'))+'</div>'
    + '<div class="sr-name">'+escapeHTML(lv.name || ('#'+id))+'</div></div>'
    + '<div class="sr-body"><div class="sr-meta"><span class="sr-diff">'+(face ? '<img src="'+face+'" alt="">' : '')+escapeHTML(lv.difficulty || '—')+'</span>'
    + '<span class="sr-creator">#'+escapeHTML(id)+' · by <b>'+escapeHTML(lv.author || '—')+'</b></span></div>'
    + '<div class="sr-stats">'
    + '<div class="sr-stat"><div class="sr-stat-k">'+escapeHTML(t('spinStatDownloads'))+'</div><div class="sr-stat-v">⬇ '+fmtNum(lv.downloads)+'</div></div>'
    + '<div class="sr-stat"><div class="sr-stat-k">'+escapeHTML(t('spinStatLikes'))+'</div><div class="sr-stat-v">♥ '+fmtNum(lv.likes)+'</div></div>'
    + '<div class="sr-stat"><div class="sr-stat-k">'+escapeHTML(t('spinStatStars'))+'</div><div class="sr-stat-v">★ '+(lv.stars||0)+'</div></div>'
    + '<div class="sr-stat"><div class="sr-stat-k">'+escapeHTML(t('spinStatLen'))+'</div><div class="sr-stat-v">'+escapeHTML(lengthLabel(lv))+'</div></div>'
    + '</div><div class="sr-actions">'
    + '<button class="modal-btn solid" id="sr-open">'+escapeHTML(t('spinOpen'))+'</button>'
    + '<button class="modal-btn ghost" id="sr-review">'+escapeHTML(t('spinReview'))+'</button>'
    + '<button class="modal-btn ghost" id="sr-again">'+escapeHTML(t('spinAgain'))+'</button>'
    + '</div></div>';
  $('spin-result').hidden = false;
  $('sr-open').addEventListener('click', function(){ hideSpinResult(); if(typeof openLevelPage === 'function') openLevelPage(id); });
  $('sr-review').addEventListener('click', function(){ hideSpinResult(); if(typeof navigateTo === 'function'){ $('level-id-input').value = id; navigateTo({ screen:'create' }); if(typeof searchLevel === 'function') searchLevel(); } });
  $('sr-again').addEventListener('click', function(){ hideSpinResult(); startSpin(); });
}
function hideSpinResult(){
  $('spin-result').hidden = true; $('sr-card').innerHTML = '';
  ui.spinning = false;
  $('spin-filters').classList.remove('locked');
  updateSpinButton(); renderIdleStrip();
}

/* ---------- filter panel ---------- */
function updateDlSlider(){
  const inp = $('sf-dl'), idx = Number(inp.value);
  inp.style.setProperty('--fill', (idx / (DL_STEPS.length - 1) * 100) + '%');
  $('sf-dl-val').textContent = idx === 0 ? t('spinDlAny') : fmtNum(DL_STEPS[idx]) + '+';
}
function buildFilters(){
  $('sf-diff-grid').innerHTML = DIFF_OPTIONS.filter(o => o.v).map(o =>
    '<button type="button" class="sf-diff-opt'+(filters.diffs.has(o.v)?' on':'')+'" data-sdiff="'+escapeHTML(o.v)+'">'+diffOptionIcon(o)+'<span>'+escapeHTML(diffOptionLabel(o))+'</span></button>').join('');
  $('sf-cat').innerHTML = SPIN_CATS.map(c =>
    '<button type="button" class="sf-seg-opt'+(filters.cat===c[0]?' on':'')+'" data-scat="'+c[0]+'">'+escapeHTML(t(c[1]))+'</button>').join('');
  $('sf-len').innerHTML = SPIN_LEN.map(l =>
    '<button type="button" class="sf-seg-opt'+(filters.len===l[0]?' on':'')+'" data-slen="'+l[0]+'">'+escapeHTML(l[1]==='lenAny'?t('lenAny'):l[1])+'</button>').join('');
  updateDlSlider();
}
function bindEvents(){
  $('sf-diff-grid').addEventListener('click', function(e){
    const b = e.target.closest('.sf-diff-opt'); if(!b || ui.spinning) return;
    const v = b.dataset.sdiff;
    if(filters.diffs.has(v)){
      if(filters.diffs.size <= 1){ toast(t('spinDiffLocked'), 'error'); return; }
      filters.diffs.delete(v); b.classList.remove('on');
    } else { filters.diffs.add(v); b.classList.add('on'); }
    b.classList.remove('pop'); void b.offsetWidth; b.classList.add('pop');
    commitFilters();
  });
  $('sf-cat').addEventListener('click', function(e){
    const b = e.target.closest('.sf-seg-opt'); if(!b || ui.spinning || b.dataset.scat === filters.cat) return;
    filters.cat = b.dataset.scat;
    qsa('#sf-cat .sf-seg-opt').forEach(x => x.classList.toggle('on', x.dataset.scat === filters.cat));
    commitFilters();
  });
  $('sf-len').addEventListener('click', function(e){
    const b = e.target.closest('.sf-seg-opt'); if(!b || ui.spinning || b.dataset.slen == null || b.dataset.slen === filters.len) return;
    filters.len = b.dataset.slen;
    qsa('#sf-len .sf-seg-opt').forEach(x => x.classList.toggle('on', x.dataset.slen === filters.len));
    commitFilters();
  });
  $('sf-dl').addEventListener('input', function(){
    filters.minDl = DL_STEPS[Number(this.value)] || 0;
    updateDlSlider();
    if(!ui.spinning) commitFilters();      /* debounced — sliders fire rapidly */
  });
  $('sf-starred').addEventListener('click', function(){
    if(ui.spinning) return;
    filters.starred = !filters.starred;
    this.classList.toggle('on', filters.starred);
    this.setAttribute('aria-checked', String(filters.starred));
    commitFilters();
  });
  $('spin-btn').addEventListener('click', startSpin);
  $('wheel-empty').addEventListener('click', function(){   /* user-initiated Retry */
    if(ui.lastState && ui.lastState.status === 'error') pool.reset(filters);
  });
  $('sr-backdrop').addEventListener('click', hideSpinResult);
  document.addEventListener('keydown', function(e){ if(e.key === 'Escape' && !$('spin-result').hidden) hideSpinResult(); });
  $('spin-back').addEventListener('click', function(){ if(typeof goBack === 'function') goBack(); });
  const open = $('spin-open');
  if(open){
    open.addEventListener('click', function(){ if(typeof navigateTo === 'function') navigateTo({ screen:'spin' }); });
    open.addEventListener('keydown', function(e){ if(e.key === 'Enter' || e.key === ' '){ e.preventDefault(); if(typeof navigateTo === 'function') navigateTo({ screen:'spin' }); } });
  }
}

/* ---------- page lifecycle (called by the existing router) ---------- */
function startSpinPage(){
  if(!ui.built){
    ui.built = true;
    buildFilters(); bindEvents();
    /* Custom Wheel mode is not part of the pool integration yet — hide it. */
    $('spin-mode').hidden = true; $('spin-custom').hidden = true; $('spin-filters').hidden = false;
  }
  ui.active = true; ui.lastTs = 0;
  if(pool.status === 'idle') pool.reset(filters);
  else { updateStatus(ui.lastState); updateSpinButton(); updateEmptyBox(ui.lastState); renderIdleStrip(); }
  cancelAnimationFrame(ui.raf);
  ui.raf = requestAnimationFrame(frame);
}
function stopSpinPage(){
  ui.active = false;
  cancelAnimationFrame(ui.raf);
  if(!$('spin-result').hidden) hideSpinResult();
}
window.startSpinPage = startSpinPage;
window.stopSpinPage = stopSpinPage;
window.refreshSpinI18n = function(){ if(ui.built){ buildFilters(); updateStatus(ui.lastState); updateSpinButton(); updateEmptyBox(ui.lastState); } };
