//! Per-item last-writer-wins sets.
//!
//! Every synced item (a server, a snippet) is an [`Entry`]: its id, the time
//! of its last change, and either its data or a deletion marker ("tombstone").
//! Merging two sets keeps, for each id, the entry with the later change, so
//! edits to different items both survive, the newer edit of one item wins,
//! and deletions don't come back. The merge is commutative, associative and
//! idempotent: devices converge whatever order they sync in.
//!
//! Change times come from [`observe`]: it compares what the app has now with
//! what it had at the last sync, so the app never has to stamp changes itself.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    /// Milliseconds since the Unix epoch of the last change to this item.
    pub modified: u64,
    /// A deletion marker: kept so the deletion wins over older copies.
    #[serde(default, skip_serializing_if = "is_false")]
    pub deleted: bool,
    /// The item itself (absent for deletion markers).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl Entry {
    pub fn live(id: impl Into<String>, modified: u64, data: Value) -> Self {
        Self { id: id.into(), modified, deleted: false, data: Some(data) }
    }

    pub fn tombstone(id: impl Into<String>, modified: u64) -> Self {
        Self { id: id.into(), modified, deleted: true, data: None }
    }

    /// Total order used to pick a winner: later change first; at the same
    /// millisecond a deletion wins, then the larger data (any fixed rule
    /// works, as long as every device applies the same one).
    fn rank(&self) -> (u64, bool, String) {
        let data = self.data.as_ref().map(|d| d.to_string()).unwrap_or_default();
        (self.modified, self.deleted, data)
    }
}

/// Stamps changes: `prev` is the set as of the last sync (or last observe),
/// `current` what the app has now. Unchanged items keep their time; new or
/// edited items get `now`; items that disappeared become deletion markers.
/// Times only move forward per item, even if the clock went back.
pub fn observe(prev: &[Entry], current: &[(String, Value)], now: u64) -> Vec<Entry> {
    let before: BTreeMap<&str, &Entry> = prev.iter().map(|e| (e.id.as_str(), e)).collect();
    let mut out: BTreeMap<String, Entry> = BTreeMap::new();
    let later = |e: Option<&&Entry>| e.map_or(now, |e| now.max(e.modified + 1));
    for (id, data) in current {
        let old = before.get(id.as_str());
        let entry = match old {
            Some(e) if !e.deleted && e.data.as_ref() == Some(data) => (*e).clone(),
            _ => Entry::live(id.clone(), later(old), data.clone()),
        };
        out.insert(id.clone(), entry);
    }
    for e in prev {
        if out.contains_key(&e.id) {
            continue;
        }
        let entry = if e.deleted { e.clone() } else { Entry::tombstone(e.id.clone(), now.max(e.modified + 1)) };
        out.insert(e.id.clone(), entry);
    }
    out.into_values().collect()
}

/// Merges two sets: for each id, the entry with the later change.
pub fn merge(a: &[Entry], b: &[Entry]) -> Vec<Entry> {
    let mut out: BTreeMap<String, Entry> = BTreeMap::new();
    for e in a.iter().chain(b) {
        match out.get(&e.id) {
            Some(cur) if cur.rank() >= e.rank() => {}
            _ => {
                out.insert(e.id.clone(), e.clone());
            }
        }
    }
    out.into_values().collect()
}

/// The items that exist (deletion markers left out), in id order.
pub fn live(set: &[Entry]) -> Vec<(String, Value)> {
    set.iter().filter(|e| !e.deleted).filter_map(|e| e.data.clone().map(|d| (e.id.clone(), d))).collect()
}

/// What changed between two sets, for "3 servers updated" style messages.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct Changes {
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
}

impl Changes {
    pub fn is_empty(&self) -> bool {
        self.added + self.updated + self.removed == 0
    }
}

/// Counts how the live items of `after` differ from those of `before`.
pub fn changes(before: &[(String, Value)], after: &[(String, Value)]) -> Changes {
    let b: BTreeMap<&str, &Value> = before.iter().map(|(k, v)| (k.as_str(), v)).collect();
    let a: BTreeMap<&str, &Value> = after.iter().map(|(k, v)| (k.as_str(), v)).collect();
    let mut c = Changes::default();
    for (k, v) in &a {
        match b.get(k) {
            None => c.added += 1,
            Some(old) if old != v => c.updated += 1,
            _ => {}
        }
    }
    c.removed = b.keys().filter(|k| !a.contains_key(*k)).count();
    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn item(id: &str, name: &str) -> (String, Value) {
        (id.into(), json!({ "id": id, "name": name }))
    }

    fn names(set: &[Entry]) -> Vec<String> {
        live(set).into_iter().map(|(_, d)| d["name"].as_str().unwrap().to_string()).collect()
    }

    #[test]
    fn observe_stamps_only_what_changed() {
        let s1 = observe(&[], &[item("a", "api"), item("b", "db")], 100);
        assert!(s1.iter().all(|e| e.modified == 100 && !e.deleted));
        // Nothing changed: times stay.
        let s2 = observe(&s1, &[item("a", "api"), item("b", "db")], 200);
        assert_eq!(s1, s2);
        // b edited, a deleted, c added.
        let s3 = observe(&s2, &[item("b", "db-2"), item("c", "cache")], 300);
        let by: BTreeMap<_, _> = s3.iter().map(|e| (e.id.as_str(), e)).collect();
        assert!(by["a"].deleted && by["a"].modified == 300 && by["a"].data.is_none());
        assert_eq!((by["b"].modified, by["c"].modified), (300, 300));
        // A deletion marker stays put while the item stays gone.
        let s4 = observe(&s3, &[item("b", "db-2"), item("c", "cache")], 400);
        assert_eq!(s3, s4);
    }

    #[test]
    fn times_never_go_backwards() {
        let s1 = observe(&[], &[item("a", "api")], 1_000);
        // The clock jumped back; the edit must still count as newer.
        let s2 = observe(&s1, &[item("a", "api-2")], 10);
        assert_eq!(s2[0].modified, 1_001);
        let s3 = observe(&s2, &[], 5);
        assert!(s3[0].deleted && s3[0].modified == 1_002);
    }

    #[test]
    fn edits_to_different_items_both_survive() {
        let base = observe(&[], &[item("a", "api"), item("b", "db")], 100);
        let laptop = observe(&base, &[item("a", "api-laptop"), item("b", "db")], 200);
        let desktop = observe(&base, &[item("a", "api"), item("b", "db-desktop")], 300);
        assert_eq!(names(&merge(&laptop, &desktop)), ["api-laptop", "db-desktop"]);
    }

    #[test]
    fn newer_edit_of_the_same_item_wins() {
        let base = observe(&[], &[item("a", "api")], 100);
        let older = observe(&base, &[item("a", "older")], 200);
        let newer = observe(&base, &[item("a", "newer")], 300);
        assert_eq!(names(&merge(&older, &newer)), ["newer"]);
        assert_eq!(names(&merge(&newer, &older)), ["newer"]);
    }

    #[test]
    fn deletions_do_not_come_back() {
        let base = observe(&[], &[item("a", "api"), item("b", "db")], 100);
        let deleted_here = observe(&base, &[item("b", "db")], 200);
        // The other device still has the old copy of a.
        let merged = merge(&deleted_here, &base);
        assert_eq!(names(&merged), ["db"]);
        // An edit made after the deletion brings it back (the user meant it).
        let edited_later = observe(&base, &[item("a", "api-edited"), item("b", "db")], 300);
        assert_eq!(names(&merge(&deleted_here, &edited_later)), ["api-edited", "db"]);
        // An edit made before the deletion doesn't.
        let edited_earlier = observe(&base, &[item("a", "api-edited"), item("b", "db")], 150);
        assert_eq!(names(&merge(&deleted_here, &edited_earlier)), ["db"]);
    }

    #[test]
    fn merge_converges_whatever_the_order() {
        let a = vec![Entry::live("x", 5, json!(1)), Entry::live("y", 9, json!("a")), Entry::tombstone("z", 7)];
        let b = vec![Entry::live("x", 6, json!(2)), Entry::live("y", 9, json!("b")), Entry::live("z", 7, json!(3))];
        let c = vec![Entry::tombstone("x", 6), Entry::live("w", 1, json!(0))];
        assert_eq!(merge(&a, &b), merge(&b, &a), "commutative, including same-millisecond ties");
        assert_eq!(merge(&merge(&a, &b), &c), merge(&a, &merge(&b, &c)), "associative");
        let ab = merge(&a, &b);
        assert_eq!(merge(&ab, &ab), ab, "idempotent");
        let by: BTreeMap<_, _> = merge(&ab, &c).into_iter().map(|e| (e.id.clone(), e)).collect();
        assert!(by["x"].deleted, "same time: the deletion wins");
        assert!(by["z"].deleted);
        assert_eq!(by["y"].data, Some(json!("b")), "same time: a fixed rule picks one");
    }

    #[test]
    fn change_counts() {
        let before = vec![item("a", "api"), item("b", "db")];
        let after = vec![item("b", "db-2"), item("c", "cache")];
        assert_eq!(changes(&before, &after), Changes { added: 1, updated: 1, removed: 1 });
        assert!(changes(&before, &before).is_empty());
    }

    #[test]
    fn entry_json_is_compact() {
        let v = serde_json::to_value(Entry::tombstone("a", 5)).unwrap();
        assert_eq!(v, json!({ "id": "a", "modified": 5, "deleted": true }));
        let v = serde_json::to_value(Entry::live("b", 6, json!({ "n": 1 }))).unwrap();
        assert_eq!(v, json!({ "id": "b", "modified": 6, "data": { "n": 1 } }));
    }
}
