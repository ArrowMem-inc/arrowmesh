//! Engine tests: the design's corpus and invariants (T1a to T11, T13), driven without sockets.
//! Secret shaped literals are built at runtime from fragments, as the gate crate's own tests do.

use super::*;
use crate::gatepath::Gate;
use std::cell::Cell;
use std::collections::VecDeque;

struct VecSrc<'a> {
    q: VecDeque<Vec<u8>>,
    done_sent: bool,
    /// Called on every poll, before the piece is handed over.
    on_poll: Option<&'a dyn Fn()>,
}

impl<'a> VecSrc<'a> {
    fn new(pieces: &[String]) -> VecSrc<'a> {
        let q = pieces.iter().map(|p| format!("data: {}\n\n", json!({"choices": [{"delta": {"content": p}}]})).into_bytes()).collect();
        VecSrc { q, done_sent: false, on_poll: None }
    }
}

impl Source for VecSrc<'_> {
    fn poll(&mut self, _tick: Duration) -> io::Result<Poll> {
        if let Some(f) = self.on_poll {
            f();
        }
        if let Some(b) = self.q.pop_front() {
            return Ok(Poll::Data(b));
        }
        if !self.done_sent {
            self.done_sent = true;
            return Ok(Poll::Data(b"data: [DONE]\n\n".to_vec()));
        }
        Ok(Poll::End)
    }
}

#[derive(Default)]
struct VecSink {
    ev: Vec<(String, Value)>,
}

impl Sink for VecSink {
    fn send(&mut self, name: &str, data: &Value) -> bool {
        self.ev.push((name.to_string(), data.clone()));
        true
    }
}

const EAGER: Params = Params { cadence: Duration::ZERO, cap: usize::MAX };

struct Run {
    out: Outcome,
    ev: Vec<(String, Value)>,
    commits: u32,
}

fn run(gate: &Gate, pieces: &[String], p: &Params) -> Run {
    let commits = Cell::new(0u32);
    let sealed = || false;
    let commit = |reply: &str| -> Result<Value, String> {
        commits.set(commits.get() + 1);
        Ok(json!({"conv": "t", "choices": [{"message": {"role": "assistant", "content": reply}}], "gate": {"prompt": "pass", "reply": "pass"}}))
    };
    let hooks = Hooks { sealed: &sealed, commit: &commit };
    let mut src = VecSrc::new(pieces);
    let mut sink = VecSink::default();
    let out = drive(gate, p, &mut src, &mut sink, &hooks);
    Run { out, ev: sink.ev, commits: commits.get() }
}

impl Run {
    fn shown(&self) -> String {
        self.ev.iter().filter(|(n, _)| n == "delta").map(|(_, d)| d["text"].as_str().unwrap().to_string()).collect()
    }
    fn terminals(&self) -> usize {
        self.ev.iter().filter(|(n, _)| matches!(n.as_str(), "done" | "blocked" | "error")).count()
    }
}

// ---- schedules ----

fn seeded(seed: u64) -> impl FnMut() -> u64 {
    let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    }
}

fn chars_of(t: &str) -> Vec<String> {
    t.chars().map(|c| c.to_string()).collect()
}

fn by_whitespace(t: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in t.chars() {
        cur.push(c);
        if c.is_whitespace() {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn random_pieces(t: &str, seed: u64) -> Vec<String> {
    let mut r = seeded(seed);
    let cs: Vec<char> = t.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < cs.len() {
        let n = 1 + (r() % 5) as usize;
        out.push(cs[i..(i + n).min(cs.len())].iter().collect());
        i += n;
    }
    out
}

fn every_split(t: &str) -> Vec<Vec<String>> {
    let idx: Vec<usize> = t.char_indices().map(|(i, _)| i).chain(std::iter::once(t.len())).collect();
    idx.iter().map(|&i| vec![t[..i].to_string(), t[i..].to_string()]).collect()
}

fn schedules(t: &str, exhaustive: bool) -> Vec<Vec<String>> {
    let mut v = vec![chars_of(t), by_whitespace(t), vec![t.to_string()]];
    v.extend((1..=4).map(|s| random_pieces(t, s)));
    if exhaustive {
        v.extend(every_split(t));
    }
    v
}

// ---- corpus ----

struct Item {
    name: String,
    text: String,
    /// Raw byte offsets of the sensitive span.
    span: (usize, usize),
}

const LEAD_WORD: &str = "the quick brown fox jumps over the lazy dog ";
const TAIL: &str = " and that is all for now.\n";

/// `n` bytes of plain words, ending in a space (or empty for 0), so what follows starts a new token.
fn lead(n: usize) -> String {
    if n == 0 {
        return String::new();
    }
    format!("{}{}", &LEAD_WORD.repeat(n / LEAD_WORD.len() + 1)[..n - 1], " ")
}

fn pad(s: &str, z: &str) -> String {
    s.chars().map(|c| format!("{c}{z}")).collect()
}

fn arabic_digits(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_digit() { char::from_u32(0x0660 + c as u32 - '0' as u32).unwrap() } else { c }).collect()
}

/// (name, the sensitive span as it appears in the text, byte offset inside it where the hidden part starts)
fn secrets() -> Vec<(&'static str, String, usize)> {
    let val = gate::random_secret_value();
    let kw = format!("{}{}", "pass", "word");
    let assigned = format!("{kw}: {val}");
    let hidden_from = kw.len() + 2;
    vec![
        ("aws", format!("AKIA{}", "A".repeat(16)), 0),
        ("sk", format!("{}{}", "sk-", "abcdefghij0123456789xyz"), 0),
        ("ghp", format!("{}{}", "ghp_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"), 0),
        ("email", concat!("jane.doe@gm", "ail.com").to_string(), 0),
        ("card_spaces", "4242 4242 4242 4242".to_string(), 0),
        ("card_dashes", "4242-4242-4242-4242".to_string(), 0),
        ("sin", "046 454 286".to_string(), 0),
        ("phone", "613 555 0199".to_string(), 0),
        ("pem_header", format!("-----BEGIN RSA {} KEY-----", "PRIVATE"), 0),
        ("assigned", assigned, hidden_from),
        ("card_zwsp", pad("4242 4242 4242 4242", "\u{200b}\u{200b}\u{00ad}"), 0),
        // Sixty invisible characters between every group of digits: the raw span of the number is far
        // wider than the window, the folded span is 19 characters (cloud review F1).
        ("card_zwsp_heavy", pad("4242 4242 4242 4242", &"\u{200b}".repeat(20)), 0),
        ("email_cyrillic_a", concat!("j\u{0430}ne.doe@gm", "ail.com").to_string(), 0),
        ("card_arabic_digits", arabic_digits("4242 4242 4242 4242"), 0),
        ("email_percent", concat!("jane.doe%40gm", "ail.com").to_string(), 0),
        ("email_json_escape", concat!("jane.doe\\u0040gm", "ail.com").to_string(), 0),
    ]
}

fn corpus() -> Vec<Item> {
    let mut out = Vec::new();
    for (name, sec, hidden_from) in secrets() {
        for l in [0usize, 10, 80, 300] {
            let pre = lead(l);
            let text = format!("{pre}{sec}{TAIL}");
            out.push(Item { name: format!("{name}/lead{l}"), text, span: (pre.len() + hidden_from, pre.len() + sec.len()) });
        }
    }
    out
}

fn b64(data: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                s.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

fn real() -> Gate {
    Gate::new(None)
}

// ---- T1a, T1b, T2, T3, T4, T5, T6, T8 over the corpus ----

#[test]
fn t1_t2_t3_t4_t6_t8_over_the_corpus_and_every_schedule() {
    let g = real();
    let (mut runs, mut early_shown, mut subset_only) = (0u32, 0u32, 0u32);
    for item in corpus() {
        let whole_cats = g.check(&item.text).expect_err(&format!("{}: the whole reply must be blocked for this to be a security item", item.name));
        let exhaustive = item.name.ends_with("lead0") || item.name.ends_with("lead80");
        for pieces in schedules(&item.text, exhaustive) {
            runs += 1;
            let r = run(&g, &pieces, &EAGER);
            // T1a: the whole reply is blocked, so the stream ends blocked. Never done.
            let Outcome::Blocked(cats) = &r.out else { panic!("{}: whole blocks but stream ended {:?}", item.name, r.out) };
            assert!(cats.iter().all(|c| whole_cats.contains(c)), "{}: categories {cats:?} vs whole {whole_cats:?}", item.name);
            if cats != &whole_cats {
                subset_only += 1;
            }
            // T3/T4: exactly one terminal, last, no done, nothing committed.
            assert_eq!(r.terminals(), 1, "{}", item.name);
            assert_eq!(r.ev.last().unwrap().0, "blocked", "{}", item.name);
            assert_eq!(r.commits, 0, "{}: vault written on a blocked stream", item.name);
            // T2: nothing of the sensitive span was shown; what was shown is a prefix that ends before it.
            let shown = r.shown();
            assert!(item.text.starts_with(&shown), "{}: shown text is not a prefix of the reply", item.name);
            assert!(shown.len() <= item.span.0, "{}: shown {} bytes, the sensitive span starts at {}", item.name, shown.len(), item.span.0);
            if !shown.is_empty() {
                early_shown += 1;
            }
            // T6: every release point sits on whitespace, never inside a token.
            let mut at = 0;
            for (n, d) in &r.ev {
                if n == "delta" {
                    at += d["text"].as_str().unwrap().len();
                    let next = item.text[at..].chars().next();
                    assert!(next.is_none_or(is_boundary), "{}: a delta ended inside a token at byte {at}", item.name);
                }
                // T8: held carries one integer field and nothing else.
                if n == "held" {
                    let o = d.as_object().unwrap();
                    assert_eq!(o.len(), 1);
                    assert!(o["chars"].is_u64());
                }
            }
        }
    }
    println!("T1a/T2 corpus: {runs} runs, {early_shown} showed text before the block, {subset_only} blocked early with a category subset of the whole");
    assert!(runs > 1000, "corpus too small: {runs}");
}

fn benign_items() -> Vec<(&'static str, String)> {
    let code = "fn add(a: i32, b: i32) -> i32 {\n    let total = a + b;\n    total\n}\n\n".repeat(40);
    let log = (0..12).map(|i| format!("build {i} ok digest {:016x}{:016x}\n", 0x1234_5678_9abc_def0u64 ^ i, 0x0fed_cba9_8765_4321u64 + i)).collect::<String>();
    vec![
        ("plain", format!("{}{}", lead(500), TAIL)),
        ("code", code),
        ("log_with_digests", log),
        ("timestamps", (0..20).map(|i| format!("ts {} ms elapsed\n", 1_700_000_000_000u64 + i * 17)).collect()),
        ("nbsp_and_curly_quotes", "He said \u{201c}hello\u{201d}\u{00a0}and left\u{00a0}at noon. It was fine.".repeat(4)),
        ("french_accents", "Voil\u{00e0} une phrase en fran\u{00e7}ais avec des accents: \u{00e9}t\u{00e9}, na\u{00ef}ve, ch\u{00e2}teau. ".repeat(6)),
        ("only_whitespace", " \n\t \u{00a0} \n".to_string()),
        ("empty", String::new()),
        ("seventeen_digit_run", "note 42424242424242427 end of note".to_string()),
    ]
}

#[test]
fn t1b_t5_benign_replies_stream_to_done_and_reconcile() {
    let g = real();
    let mut blocked_where_whole_passes = 0;
    for (name, text) in benign_items() {
        assert!(g.check(&text).is_ok(), "{name}: the benign item must pass whole");
        for pieces in schedules(&text, text.len() < 200) {
            let r = run(&g, &pieces, &EAGER);
            if let Outcome::Blocked(_) = r.out {
                blocked_where_whole_passes += 1;
                continue;
            }
            assert_eq!(r.out, Outcome::Done, "{name}");
            // T5: the deltas concatenate to the reply, and the done payload carries the same text.
            assert_eq!(r.shown(), text, "{name}");
            let done = &r.ev.last().unwrap().1;
            assert_eq!(done["choices"][0]["message"]["content"].as_str().unwrap(), text, "{name}");
            assert_eq!((r.commits, r.terminals()), (1, 1), "{name}");
        }
    }
    println!("T1b: {blocked_where_whole_passes} streams blocked where the whole reply passes (benign set)");
    assert_eq!(blocked_where_whole_passes, 0, "operability regression on the benign set");
}

#[test]
fn seventeen_digit_run_is_not_blocked_because_the_cut_never_scans_a_half_token() {
    // The hazard is real: a 16 digit Luhn valid run at the END of the buffer matches the card rule
    // (end of string is a word boundary), while the same run with a 17th digit does not.
    let g = real();
    assert!(g.check_rules("note 4242424242424242").is_err());
    assert!(g.check_rules("note 42424242424242427").is_ok());
    let r = run(&g, &chars_of("note 42424242424242427 end"), &EAGER);
    assert_eq!(r.out, Outcome::Done);
}

// ---- the residuals, shown then retracted (attacks 7, 8, 11) ----

fn lcg_b64(n: usize, seed: u64) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut r = seeded(seed);
    (0..n).map(|_| A[(r() % 64) as usize] as char).collect()
}

fn assert_retracts(name: &str, g: &Gate, text: &str, pieces: Vec<String>) -> usize {
    let r = run(g, &pieces, &EAGER);
    assert!(matches!(r.out, Outcome::Blocked(_)), "{name}: {:?}", r.out);
    assert_eq!(r.terminals(), 1, "{name}");
    assert!(r.ev.iter().all(|(n, _)| n != "done"), "{name}: done after blocked");
    assert_eq!(r.commits, 0, "{name}: vault written");
    assert!(text.starts_with(&r.shown()), "{name}");
    r.shown().len()
}

#[test]
fn t3_spaced_base64_beyond_the_window_is_retracted_before_done() {
    let g = real();
    let plain = format!("the access key id for the build account is AKIA{} and this note is long enough to need more base64 groups", "A".repeat(16));
    let enc = b64(plain.as_bytes());
    let spaced: Vec<String> = enc.as_bytes().chunks(4).map(|c| String::from_utf8(c.to_vec()).unwrap()).collect();
    let body = spaced.join(" ");
    assert!(body.len() > 2 * W, "{}", body.len());
    // No lead: the whitespace stripped view glues a lead into the run and the decode then misaligns.
    let text = format!("{body}\n");
    assert!(g.check(&text).is_err(), "this item must be one the whole scan catches");
    let shown = assert_retracts("spaced b64", &g, &text, by_whitespace(&text));
    println!("attack 7: shown {shown} bytes of {} before the retraction", text.len());
    assert!(shown > 0, "the residual is only a residual if text was shown first");
}

#[test]
fn t3_late_opaque_blob_is_retracted_before_done() {
    let g = real();
    let mut text = lead(200);
    for i in 0..10 {
        text.push_str(&format!(" {}", lcg_b64(120, 100 + i)));
    }
    text.push_str("\nend.\n");
    assert!(g.check(&text).is_err(), "this item must be one the whole scan catches");
    let shown = assert_retracts("late blob", &g, &text, by_whitespace(&text));
    println!("attack 8: shown {shown} bytes of {} before the retraction", text.len());
    assert!(shown > 0);
}

#[test]
fn t10_model_runs_once_at_the_end_and_a_late_personal_sentence_retracts_all() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    let calls = Arc::new(AtomicU32::new(0));
    let c2 = calls.clone();
    let personal = "Note to self: my neighbour's divorce hearing is on the 3rd, his address is 12 Elm.";
    // The model layer is a stub: PERSONAL when the text mentions the hearing, counting its calls.
    let g = Gate::with_scans(
        |t| gate::scan_with(t, None),
        move |t| {
            c2.fetch_add(1, Ordering::SeqCst);
            let mut v = gate::scan_with(t, None);
            if t.contains("divorce hearing") {
                v.pass = false;
                v.reasons.push("model:personal".into());
            }
            v
        },
    );
    let text = format!("{} {}\n", "The quarterly build is green and the release notes are ready for review. ".repeat(10), personal);
    assert!(gate::scan_with(&text, None).pass, "the rules alone pass this text");
    let pieces = by_whitespace(&text);
    let commits = Cell::new(0u32);
    let sealed = || false;
    let commit = |_: &str| -> Result<Value, String> {
        commits.set(commits.get() + 1);
        Ok(json!({}))
    };
    let hooks = Hooks { sealed: &sealed, commit: &commit };
    let mut src = VecSrc::new(&pieces);
    let poll_calls = calls.clone();
    let seen_polls = Cell::new(0u32);
    let on_poll = || {
        seen_polls.set(seen_polls.get() + 1);
        // Every poll while chunks are still arriving must find the model untouched.
        assert_eq!(poll_calls.load(Ordering::SeqCst), 0, "model called before the last chunk");
    };
    src.on_poll = Some(&on_poll);
    let mut sink = VecSink::default();
    let out = drive(&g, &EAGER, &mut src, &mut sink, &hooks);
    assert!(seen_polls.get() as usize > pieces.len(), "the source was polled through every chunk");
    assert_eq!(out, Outcome::Blocked(vec!["model:personal".to_string()]));
    assert_eq!(calls.load(Ordering::SeqCst), 1, "the model layer runs exactly once");
    assert_eq!(commits.get(), 0);
    let r = Run { out, ev: sink.ev, commits: 0 };
    assert!(!r.shown().is_empty(), "text was shown before the retraction");
    assert!(r.ev.iter().all(|(n, _)| n != "done"));
}

// ---- T7, T7b ----

#[test]
fn t7_the_boundary_and_the_gate_use_one_whitespace_predicate() {
    let gate_src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../arrowmem-gate/src/decode.rs")).expect("gate source");
    assert!(gate_src.contains("filter(|c| !c.is_whitespace())"), "decode.rs no longer strips with char::is_whitespace");
    assert!(!gate_src.contains("is_ascii_whitespace"));
    let mine = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/stream.rs")).unwrap();
    let prod = mine.split("#[cfg(test)]").next().unwrap();
    assert_eq!(prod.matches("is_whitespace()").count(), 1, "a second whitespace predicate appeared in the engine");
    assert!(!prod.contains("is_ascii_whitespace"));
    for c in ['\u{00a0}', '\u{3000}', '\u{2028}', ' ', '\n', '\t', '\u{1680}'] {
        assert!(is_boundary(c));
    }
    for c in ['\u{200b}', '\u{00ad}', '\u{2060}', '\u{feff}', 'a', '\u{0301}'] {
        assert!(!is_boundary(c), "{c:?} is not White_Space");
    }
}

fn random_unicode(seed: u64, n: usize) -> String {
    const POOL: &[char] = &[
        'a', 'b', 'Z', '0', '4', '2', '@', '.', '-', ' ', ' ', '\n', '\t', '\u{00a0}', '\u{3000}', '\u{2028}', '\u{2003}', '\u{200b}', '\u{00ad}', '\u{2060}', '\u{feff}', '\u{00a8}', '\u{00af}',
        '\u{0430}', '\u{0435}', '\u{0664}', '\u{0662}', '\u{0301}', '\u{fb03}', '\u{ff14}', '\u{2800}', '\u{1f600}', '\u{fe0f}', '\u{3164}', '\u{0131}',
    ];
    let mut r = seeded(seed);
    (0..n).map(|_| POOL[(r() % POOL.len() as u64) as usize]).collect()
}

#[test]
fn t7b_fold_keeps_every_raw_boundary_and_a_prefix_at_a_boundary_folds_to_a_prefix() {
    let (mut checked, mut created_cases) = (0u32, 0u32);
    for seed in 1..=400u64 {
        let s = random_unicode(seed, 30);
        let f = fold(&s);
        // Safety direction: no whitespace is removed by the fold.
        let raw_ws = s.chars().filter(|c| is_boundary(*c)).count();
        let folded_ws = f.chars().filter(|c| is_boundary(*c)).count();
        assert!(folded_ws >= raw_ws, "fold removed a boundary: seed {seed}");
        if folded_ws > raw_ws {
            created_cases += 1;
        }
        for (p, c) in s.char_indices() {
            if is_boundary(c) {
                checked += 1;
                // What a prefix scan sees is a prefix of what the whole scan sees.
                assert!(f.starts_with(&fold(&s[..p])), "fold of a prefix is not a prefix of the fold: seed {seed} at {p}");
            }
        }
    }
    println!("T7b: {checked} boundaries checked, {created_cases} of 400 strings had the fold CREATE a boundary");
    assert!(checked > 500);
}

#[test]
fn t7b_pinned_finding_the_fold_can_create_a_boundary_it_never_removes_one() {
    // U+00A8 (diaeresis) is not White_Space but NFKC maps it to a space plus a combining mark, and the
    // fold drops the mark. The folded view has a space the raw text does not. Safe direction: the
    // raw cut simply holds more. Pinned so a change in the gate's fold shows up here.
    let s = format!("AKIA{}{}", "\u{00a8}", "A".repeat(16));
    assert!(!s.chars().any(is_boundary));
    assert!(fold(&s).chars().any(is_boundary));
    let mut r = Releaser::default();
    r.push(&s);
    assert_eq!(r.cut(), None, "no raw boundary, so nothing is scannable or releasable");
}

// ---- release window ----

#[test]
fn window_is_measured_on_the_folded_view_so_padding_buys_nothing() {
    let mut r = Releaser::default();
    // 20 words of 3 letters, each followed by 60 zero width characters: raw span is huge, folded span small.
    let zw: String = "\u{200b}".repeat(60);
    let text: String = (0..20).map(|_| format!("abc{zw} ")).collect();
    r.push(&text);
    r.push("tail");
    let cut = r.cut().unwrap();
    let p = r.release_point(cut);
    assert!(p > 0, "something should be releasable");
    let kept = fold(&r.text()[p..cut]).chars().count();
    assert!(kept >= W, "kept {kept} folded characters, window is {W}");
    // The next boundary later would leave fewer than W folded characters.
    let later = r.text()[..cut].char_indices().find(|(i, c)| is_boundary(*c) && *i > p).map(|(i, _)| i);
    if let Some(q) = later {
        assert!(fold(&r.text()[q..cut]).chars().count() < W);
    }
    // And raw padding alone does not release anything: 5 padded words are under the window folded.
    let mut r2 = Releaser::default();
    r2.push(&(0..5).map(|_| format!("abc{zw} ")).collect::<String>());
    r2.push("tail");
    let cut2 = r2.cut().unwrap();
    assert_eq!(r2.release_point(cut2), 0);
}

#[test]
fn held_never_drops_below_the_window_until_the_end() {
    let g = real();
    let text = "one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen\n";
    let r = run(&g, &by_whitespace(text), &EAGER);
    assert_eq!(r.out, Outcome::Done);
    let mut shown = 0;
    for (n, d) in &r.ev {
        if n == "delta" {
            shown += d["text"].as_str().unwrap().len();
        }
        // Once anything is released, at least a window stays behind it.
        if n == "held" && shown > 0 {
            assert!(d["chars"].as_u64().unwrap() as usize >= W, "held {} < W", d["chars"]);
        }
    }
    assert_eq!(shown, text.len());
}

// ---- T11, cap, lock, commit failure ----

#[test]
fn t11_blocklist_guard() {
    let dir = crate::testutil::tmp("bl");
    let f = |name: &str, body: &str| {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p.to_string_lossy().into_owned()
    };
    assert!(blocklist_fits(None));
    assert!(blocklist_fits(Some(&f("ok", "two words\nanother phrase\n"))));
    assert!(blocklist_fits(Some(&f("edge64", &format!("{}\n", "a".repeat(64))))));
    assert!(!blocklist_fits(Some(&f("edge65", &format!("{}\n", "a".repeat(65))))));
    // Measured folded: a short word padded with zero width characters still fits.
    assert!(blocklist_fits(Some(&f("padded", &format!("{}\n", pad("word", &"\u{200b}".repeat(100)))))));
    assert!(!blocklist_fits(Some(dir.join("missing").to_str().unwrap())));
}

#[test]
fn past_the_cap_nothing_more_is_scanned_or_released_until_done() {
    let g = real();
    let text = format!("{}{}", lead(2000), TAIL);
    let p = Params { cadence: Duration::ZERO, cap: 600 };
    let r = run(&g, &by_whitespace(&text), &p);
    assert_eq!(r.out, Outcome::Done);
    let deltas: Vec<&(String, Value)> = r.ev.iter().filter(|(n, _)| n == "delta").collect();
    let (last, early) = deltas.split_last().unwrap();
    let early_len: usize = early.iter().map(|(_, d)| d["text"].as_str().unwrap().len()).sum();
    assert!(early_len <= 600, "released {early_len} bytes before the cap");
    assert!(last.1["text"].as_str().unwrap().len() > 1000);
    assert_eq!(r.shown(), text);
}

#[test]
fn a_lock_mid_stream_ends_in_one_error_and_writes_nothing() {
    let g = real();
    let polls = Cell::new(0u32);
    let sealed = || {
        polls.set(polls.get() + 1);
        polls.get() > 5
    };
    let commits = Cell::new(0u32);
    let commit = |_: &str| -> Result<Value, String> {
        commits.set(1);
        Ok(json!({}))
    };
    let hooks = Hooks { sealed: &sealed, commit: &commit };
    let mut src = VecSrc::new(&chars_of("a long enough reply to still be streaming when the vault is sealed"));
    let mut sink = VecSink::default();
    assert_eq!(drive(&g, &EAGER, &mut src, &mut sink, &hooks), Outcome::Error);
    assert_eq!(commits.get(), 0);
    let last = sink.ev.last().unwrap();
    assert_eq!((last.0.as_str(), last.1["error"].as_str().unwrap()), ("error", "vault locked"));
    assert_eq!(sink.ev.iter().filter(|(n, _)| matches!(n.as_str(), "done" | "blocked" | "error")).count(), 1);
}

#[test]
fn a_vault_write_failure_is_an_error_event_and_the_held_text_is_never_sent() {
    let g = real();
    let sealed = || false;
    let commit = |_: &str| -> Result<Value, String> { Err("vault write failed".into()) };
    let hooks = Hooks { sealed: &sealed, commit: &commit };
    let text = format!("{}{}", lead(400), TAIL);
    let mut src = VecSrc::new(&by_whitespace(&text));
    let mut sink = VecSink::default();
    assert_eq!(drive(&g, &EAGER, &mut src, &mut sink, &hooks), Outcome::Error);
    let shown: String = sink.ev.iter().filter(|(n, _)| n == "delta").map(|(_, d)| d["text"].as_str().unwrap().to_string()).collect();
    assert!(shown.len() < text.len(), "the tail must not be flushed when the vault refuses");
    assert_eq!(sink.ev.last().unwrap().1["error"], "vault write failed; reply withheld");
}

#[test]
fn a_dropped_upstream_without_done_is_an_error_not_a_done() {
    struct Dies(bool);
    impl Source for Dies {
        fn poll(&mut self, _: Duration) -> io::Result<Poll> {
            if !self.0 {
                self.0 = true;
                return Ok(Poll::Data(format!("data: {}\n\n", json!({"choices": [{"delta": {"content": "partial reply "}}]})).into_bytes()));
            }
            Ok(Poll::End)
        }
    }
    let g = real();
    let sealed = || false;
    let commit = |_: &str| -> Result<Value, String> { panic!("committed a partial reply") };
    let hooks = Hooks { sealed: &sealed, commit: &commit };
    let mut sink = VecSink::default();
    assert_eq!(drive(&g, &EAGER, &mut Dies(false), &mut sink, &hooks), Outcome::Error);
}

#[test]
fn a_client_that_is_gone_ends_the_stream_without_a_terminal() {
    struct Gone;
    impl Sink for Gone {
        fn send(&mut self, _: &str, _: &Value) -> bool {
            false
        }
    }
    let g = real();
    let sealed = || false;
    let commit = |_: &str| -> Result<Value, String> { panic!("committed for a client that left") };
    let hooks = Hooks { sealed: &sealed, commit: &commit };
    let text = format!("{}{}", lead(400), TAIL);
    let mut src = VecSrc::new(&by_whitespace(&text));
    assert_eq!(drive(&g, &EAGER, &mut src, &mut Gone, &hooks), Outcome::Gone);
}

// ---- upstream parsing ----

#[test]
fn upstream_parser_handles_split_lines_crlf_and_ignores_noise() {
    let mut p = UpstreamSse::default();
    let ev = format!("data: {}\r\n\r\n", json!({"choices": [{"delta": {"content": "hi "}}]}));
    let (a, b) = ev.as_bytes().split_at(9);
    assert!(p.feed(a).unwrap().is_empty());
    let got = p.feed(b).unwrap();
    assert!(matches!(&got[..], [Piece::Text(t)] if t == "hi "));
    let noise = b": comment\nevent: x\ndata: {not json}\ndata: {\"choices\":[{\"delta\":{}}]}\ndata: [DONE]\n";
    let got = p.feed(noise).unwrap();
    assert!(matches!(&got[..], [Piece::Done]));
    assert!(p.feed(&vec![b'x'; (1 << 20) + 1]).is_err());
}

// ---- T13 ----

#[test]
fn t13_cost_a_64_kib_benign_reply_streams_to_done_and_the_scan_work_is_bounded() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    let scans = Arc::new(AtomicU64::new(0));
    let scanned = Arc::new(AtomicU64::new(0));
    let (s2, b2) = (scans.clone(), scanned.clone());
    let g = Gate::with_scans(
        move |t| {
            s2.fetch_add(1, Ordering::SeqCst);
            b2.fetch_add(t.len() as u64, Ordering::SeqCst);
            gate::scan_with(t, None)
        },
        |t| gate::scan_with(t, None),
    );
    let text = format!("{}{}", lead(64 * 1024), TAIL);
    assert!(gate::scan_with(&text, None).pass);
    let pieces: Vec<String> = text.as_bytes().chunks(64).map(|c| String::from_utf8(c.to_vec()).unwrap()).collect();
    let t0 = Instant::now();
    let r = run(&g, &pieces, &Params { cadence: Duration::ZERO, cap: RELEASE_CAP });
    let el = t0.elapsed();
    assert_eq!(r.out, Outcome::Done);
    assert_eq!(r.shown(), text);
    let (n, bytes) = (scans.load(Ordering::SeqCst), scanned.load(Ordering::SeqCst));
    println!("T13: {} byte reply in {} pieces: {n} prefix scans over {bytes} bytes in total, {el:?}", text.len(), pieces.len());
    assert!(bytes <= n * (RELEASE_CAP as u64 + 64), "scanned more than the cap allows");
    assert!(n < pieces.len() as u64 / 2, "scans did not stop at the cap");
}

// ---- the decode trigger hold and the lock check before every delta ----

fn card_groups() -> [String; 4] {
    // built from fragments, as the gate crate's own tests do
    [format!("{}{}", "41", "11"), format!("{}{}", "11", "11"), format!("{}{}", "11", "11"), format!("{}{}", "11", "11")]
}

fn ent_padded(s: &str, w: usize) -> String {
    s.chars().map(|c| format!("&#{:0w$};", c as u32, w = w)).collect()
}

fn chunked_by(t: &str, n: usize) -> Vec<String> {
    t.chars().collect::<Vec<_>>().chunks(n).map(|c| c.iter().collect()).collect()
}

#[test]
fn a2_zero_padded_entities_release_a_card_in_part() {
    let g = real();
    let filler = "Here is the number you asked about, written out slowly so it is easy to read: ";
    for pad in [5usize, 6, 7, 8] {
        let enc: Vec<String> = card_groups().iter().map(|x| ent_padded(x, pad)).collect();
        let reply = format!("{filler}{} thanks", enc.join(" "));
        assert!(g.check(&reply).is_err(), "pad {pad}: the whole reply must block, or this test proves nothing");
        for piece in [3usize, 7, 19] {
            let r = run(&g, &chunked_by(&reply, piece), &EAGER);
            assert!(matches!(r.out, Outcome::Blocked(_)), "pad {pad} piece {piece}: {:?}", r.out);
            let shown = r.shown();
            for (i, e) in enc.iter().enumerate() {
                assert!(!shown.contains(e.as_str()), "pad {pad} piece {piece}: group {} was shown before blocked", i + 1);
            }
            assert!(!shown.contains("&#"), "pad {pad} piece {piece}: encoded text was released");
            assert_eq!(r.terminals(), 1);
            assert_eq!(r.commits, 0);
        }
    }
}

#[test]
fn text_before_the_trigger_still_streams_and_a_clean_reply_with_a_trigger_ends_in_done() {
    let g = real();
    let lead = words_for_test(12);
    let reply = format!("{lead}and then a percent escape %41 appears, followed by a long tail of plain words: {lead}");
    let r = run(&g, &chunked_by(&reply, 7), &EAGER);
    assert_eq!(r.out, Outcome::Done);
    assert_eq!(r.shown(), reply);
    // something was released before the trigger arrived, and nothing from the trigger on until the end
    let first_delta = r.ev.iter().position(|(n, _)| n == "delta").expect("a delta");
    let trig_at = reply.find("%41").unwrap();
    let before: String = r.ev.iter().filter(|(n, _)| n == "delta").take(r.ev.iter().filter(|(n, _)| n == "delta").count() - 1).map(|(_, d)| d["text"].as_str().unwrap().to_string()).collect();
    assert!(first_delta < r.ev.len() - 1);
    assert!(before.len() < trig_at, "text at or past the trigger was released before the end: {} of {}", before.len(), trig_at);
}

fn words_for_test(n: usize) -> String {
    "the quick brown fox jumps over the lazy dog ".repeat(n)
}

#[test]
fn the_trigger_set_matches_what_the_decoder_transforms() {
    for yes in ["&#52;", "a &#x34; b", "100%41", "x \\u0041 y", "x \\x41 y", "xn--a-ecp.ru", "XN--a-ecp.ru", "QUJDREVGR0hJSktMTU5P", "deadbeefcafebabe0123456789abcdef", "\u{ff06}\u{ff03}52;", "&\u{200b}#52;"] {
        assert!(has_decode_trigger(yes), "should trigger: {yes:?}");
    }
    for no in ["", "plain words only, nothing else.", "50% off", "100 % sure", "a \\n b", "path\\to", "&amp; and # sign", "xn- not", "short-run-only and more", "x\\u12 y"] {
        assert!(!has_decode_trigger(no), "should not trigger: {no:?}");
    }
    // The set is the decoder's: each positive really changes under a gate view, each negative does not need to.
    use gate::decode::{html_numeric_decode, json_unescape, percent_decode, punycode_view};
    assert_ne!(html_numeric_decode("&#52;"), "&#52;");
    assert_ne!(percent_decode("%41", false), "%41");
    assert_ne!(json_unescape("\\u0041"), "\\u0041");
    assert_ne!(json_unescape("\\x41"), "\\x41");
    assert_ne!(punycode_view("xn--a-ecp.ru"), "xn--a-ecp.ru");
}

#[test]
fn a3_delta_after_the_lock() {
    let g = real();
    let pieces = chunked_by(&words_for_test(8), 10);
    let locked = Cell::new(false);
    let polls = Cell::new(0u32);
    let flip = || {
        polls.set(polls.get() + 1);
        if polls.get() == 12 {
            locked.set(true); // the owner locks while the poll waits
        }
    };
    struct Sk<'a> {
        ev: Vec<(String, bool)>,
        locked: &'a Cell<bool>,
    }
    impl Sink for Sk<'_> {
        fn send(&mut self, n: &str, _d: &Value) -> bool {
            self.ev.push((n.to_string(), self.locked.get()));
            true
        }
    }
    let sealed = || locked.get();
    let commit = |_: &str| -> Result<Value, String> { Err("vault locked".into()) };
    let hooks = Hooks { sealed: &sealed, commit: &commit };
    let mut src = VecSrc::new(&pieces);
    src.on_poll = Some(&flip);
    let mut sink = Sk { ev: vec![], locked: &locked };
    let out = drive(&g, &EAGER, &mut src, &mut sink, &hooks);
    assert_eq!(out, Outcome::Error);
    assert!(polls.get() >= 12, "the lock never flipped, the test proves nothing");
    let before = sink.ev.iter().filter(|(n, l)| n == "delta" && !*l).count();
    let after = sink.ev.iter().filter(|(n, l)| n == "delta" && *l).count();
    assert!(before >= 1, "no delta went out before the lock, the test proves nothing");
    assert_eq!(after, 0, "a delta was sent after the lock returned");
}

#[test]
fn a_lock_between_the_commit_and_the_tail_releases_no_tail() {
    let g = real();
    let locked = Cell::new(false);
    let sealed = || locked.get();
    let commit = |_: &str| -> Result<Value, String> {
        locked.set(true);
        Ok(json!({}))
    };
    let hooks = Hooks { sealed: &sealed, commit: &commit };
    let mut src = VecSrc::new(&chars_of("a short reply with no release yet"));
    let mut sink = VecSink::default();
    assert_eq!(drive(&g, &EAGER, &mut src, &mut sink, &hooks), Outcome::Error);
    assert!(sink.ev.iter().all(|(n, _)| n != "delta"), "a tail was released after the lock");
}
