/*
 * Client-side Geometry Dash wheel buffer.
 *
 * This module deliberately does not claim that a third-party API has been
 * searched exhaustively. It builds a bounded, safe pool for the roulette UI.
 * A repeated page, an empty page, consecutive no-progress batches, or the
 * page ceiling stops the worker. None of those conditions can cause a fetch
 * loop.
 */

const DEFAULTS = {
  targetSize: 80,             // Keep this between 50 and 100 for this UI.
  pagesPerBatch: 4,
  maxPages: 1500,             // A hard safety ceiling, independent of API behavior.
  maxStaleBatches: 2
};

function copyFilters(filters){
  return {
    diffs: new Set(filters.diffs || []),
    cat: filters.cat || 'recent',
    len: filters.len || '',
    minDl: Number(filters.minDl || 0),
    starred: Boolean(filters.starred)
  };
}

function normalDifficulty(level){
  const value = String(level.difficulty || '').toLowerCase().trim();
  return !value || value === 'n/a' || value === 'unrated' ? 'na' : value;
}

function isEligible(level, filters){
  return filters.diffs.has(normalDifficulty(level))
    && Number(level.downloads || 0) >= filters.minDl
    && (!filters.starred || Number(level.stars || 0) > 0);
}

function pageUrl(filters, page){
  const params = new URLSearchParams({ count:'10', page:String(page), type:filters.cat });
  if(filters.len !== '') params.set('length', filters.len);
  return 'https://gdbrowser.com/api/search/*?' + params.toString();
}

function randomItem(items){
  return items[Math.floor(Math.random() * items.length)];
}

/*
 * onUpdate receives an immutable summary after every meaningful transition.
 * Use summary.status to drive the UI:
 *
 *   warming  -> show progress / disable Spin
 *   ready    -> target reached; enable Spin
 *   settled  -> source stopped with a smaller usable pool; enable Spin if >= 2
 *   empty    -> source returned an actual empty page before finding a match
 *   limited  -> source repeated/capped; do not say “no matches”
 *   error    -> request failed; offer a user-initiated Retry button
 */
export class BufferedWheelPool {
  constructor(options = {}){
    this.options = Object.assign({}, DEFAULTS, options);
    this.onUpdate = options.onUpdate || function(){};
    this.runId = 0;
    this.controller = null;
    this.filters = null;
    this.resetState();
  }

  resetState(){
    this.items = new Map();              // eligible levels, keyed by level ID
    this.rawIds = new Set();             // all IDs, including ineligible levels
    this.pageFingerprints = new Set();   // ordered ID lists returned by each page
    this.nextPage = 0;
    this.pagesScanned = 0;
    this.staleBatches = 0;
    this.status = 'idle';
    this.stopReason = null;
  }

  snapshot(){
    return Object.freeze({
      status: this.status,
      stopReason: this.stopReason,
      poolSize: this.items.size,
      targetSize: this.options.targetSize,
      pagesScanned: this.pagesScanned,
      canSpin: (this.status === 'ready' || this.status === 'settled') && this.items.size >= 2,
      levels: Array.from(this.items.values())
    });
  }

  notify(){ this.onUpdate(this.snapshot()); }

  /* Call this on every committed filter change. The previous run is aborted
     rather than allowed to update the pool after a newer selection. */
  reset(filters){
    if(this.controller) this.controller.abort();
    this.controller = new AbortController();
    this.runId++;
    this.filters = copyFilters(filters);
    this.resetState();
    this.status = 'warming';
    this.notify();
    void this.warm(this.runId, this.controller.signal);
  }

  async getPage(page, signal){
    const response = await fetch(pageUrl(this.filters, page), { signal });
    if(!response.ok) throw new Error('Geometry Dash search returned HTTP ' + response.status);
    const data = await response.json();
    if(data === '-1' || !Array.isArray(data) || data.length === 0) return { kind:'empty' };

    const ids = data.map(function(level){ return level && level.id != null ? String(level.id) : '?'; });
    return { kind:'page', levels:data, fingerprint:ids.join('|') };
  }

  shouldIgnore(run, signal){ return run !== this.runId || signal.aborted; }

  finish(status, reason){
    this.status = status;
    this.stopReason = reason;
    this.notify();
  }

  async warm(run, signal){
    try{
      while(!this.shouldIgnore(run, signal) && this.items.size < this.options.targetSize){
        if(this.pagesScanned >= this.options.maxPages){
          this.finish(this.items.size ? 'settled' : 'limited', 'page-limit');
          return;
        }

        const firstPage = this.nextPage;
        const batchPages = [];
        for(let i = 0; i < this.options.pagesPerBatch && firstPage + i < this.options.maxPages; i++){
          batchPages.push(firstPage + i);
        }
        const results = await Promise.all(batchPages.map((page) => this.getPage(page, signal)));
        if(this.shouldIgnore(run, signal)) return;

        let rawIdsAdded = 0;
        for(let i = 0; i < results.length; i++){
          const result = results[i];
          this.nextPage = batchPages[i] + 1;
          this.pagesScanned++;

          if(result.kind === 'empty'){
            this.finish(this.items.size ? 'settled' : 'empty', 'empty-page');
            return;
          }

          /* The endpoint may silently clamp huge page numbers and return the
             same content. Fingerprinting makes that a finite condition. */
          if(this.pageFingerprints.has(result.fingerprint)){
            this.finish(this.items.size ? 'settled' : 'limited', 'repeated-page');
            return;
          }
          this.pageFingerprints.add(result.fingerprint);

          result.levels.forEach((level) => {
            if(!level || level.id == null) return;
            const id = String(level.id);
            if(!this.rawIds.has(id)){
              this.rawIds.add(id);
              rawIdsAdded++;
            }
            if(isEligible(level, this.filters)) this.items.set(id, level);
          });

          if(this.items.size >= this.options.targetSize){
            this.finish('ready', 'target-reached');
            return;
          }
        }

        /* Unique raw IDs matter here, not only eligible levels: a strict
           filter can legitimately skip many pages before finding a match. */
        this.staleBatches = rawIdsAdded ? 0 : this.staleBatches + 1;
        if(this.staleBatches >= this.options.maxStaleBatches){
          this.finish(this.items.size ? 'settled' : 'limited', 'no-progress');
          return;
        }
        this.notify();
      }

      if(!this.shouldIgnore(run, signal)) this.finish('ready', 'target-reached');
    }catch(error){
      if(error && error.name === 'AbortError') return;
      if(!this.shouldIgnore(run, signal)) this.finish('error', 'request-failed');
    }
  }

  /* This method is intentionally pure: it never starts or awaits a fetch.
     Feed plan.frames to the 19 visual cards, then land on plan.winner. */
  spinPlan(frameCount = 20){
    const candidates = Array.from(this.items.values());
    if(candidates.length < 2) return null;
    const winner = randomItem(candidates);
    const frames = [];
    for(let i = 0; i < Math.max(1, frameCount - 1); i++) frames.push(randomItem(candidates));
    frames.push(winner);
    return { frames:frames, winner:winner };
  }
}

/* Example integration with the existing page:

const pool = new BufferedWheelPool({
  targetSize: 80,
  onUpdate: function(state){
    setPoolStatus(state); // status message/progress from state.pagesScanned
    $('spin-btn').disabled = !state.canSpin;
    if(state.status === 'empty') showEmpty('No levels found in this source.');
    if(state.status === 'limited') showEmpty('Search range reached; try broader filters.');
  }
});

function onCommittedFilterChange(){
  pool.reset(spinFilters); // debounce slider input by ~200 ms
}

function startSpin(){
  const plan = pool.spinPlan(20);
  if(!plan) return;
  animateWheel(plan.frames, plan.winner); // do not fetch in this function
}
*/
