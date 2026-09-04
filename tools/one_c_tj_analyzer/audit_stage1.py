#!/usr/bin/env python3
"""Independent numerical acceptance checks on saved results; JSON to stdout only.

Does not parse TJ, open provenance paths, generate reports or modify inputs.
Supported audit scope: all registered slices, full series with saved CALL times.
Production verification of arbitrary slice selections remains verify_slices.py.
"""
from __future__ import annotations

import argparse
import collections
import csv
from decimal import Decimal
import hashlib
import json
import math
from pathlib import Path
import sys

from slice_config import REGISTERED_SLICES, SliceError, normalize_config
from slice_input import load_bundle

AUDIT_VERSION = "1.1.0"
UNKNOWN_USERS = {"", "(unknown)", "(not specified)"}


def require(condition, message):
    if not condition:
        raise SliceError("Independent audit: " + message)


def rows(path):
    previous_limit = csv.field_size_limit(16*1024*1024)
    try:
        with path.open(encoding="utf-8-sig", newline="") as stream:
            yield from csv.DictReader(stream)
    finally:
        csv.field_size_limit(previous_limit)


def check(row, expected, label):
    for field, value in expected.items():
        actual = row[field]
        if isinstance(value, (dict, list, bool)):
            valid = json.loads(actual) == value
        elif value is None:
            valid = actual == ""
        elif isinstance(value, int):
            valid = actual != "" and Decimal(actual) == value
        elif isinstance(value, float):
            valid = actual != "" and math.isclose(float(actual), value, rel_tol=1e-12, abs_tol=1e-8)
        else:
            valid = actual == value
        require(valid, f"{label}.{field}: {actual!r} != {value!r}")


def ratio(n, d):
    return n / d if d else None


def stats(values):
    v = sorted(values)
    n = len(v)
    if not n:
        return dict.fromkeys(("sum", "avg", "median", "p95", "p99", "max"))
    # Integer nearest-rank indices, deliberately not the production percentile helper.
    return {"sum": sum(v), "avg": sum(v) / n, "median": (v[(n-1)//2] + v[n//2]) / 2,
            "p95": v[(95*n+99)//100-1], "p99": v[(99*n+99)//100-1], "max": v[-1]}


def operation(cs):
    n = len(cs)
    duration = stats([c["duration_us"] for c in cs])
    r = {"count": n, **{("duration_us_sum" if k == "sum" else k + "_us"): v for k, v in duration.items()}}
    for s in (1, 5, 10, 30):
        r[f"duration_gt_{s}s_count"] = sum(c["duration_us"] > s*1_000_000 for c in cs) if n else None
    db = sum(c["db_count"] for c in cs)
    db_us = sum(c["db_duration_us"] for c in cs)
    r.update(db_count_sum=db if n else None, db_per_call=ratio(db, n),
             db_duration_us_sum=db_us if n else None, db_seconds_per_call=ratio(db_us, n*1_000_000))
    for f in ("cpu_us", "in_bytes", "out_bytes"):
        v = [c[f] for c in cs if c[f] is not None]
        r.update({f+"_sum": sum(v) if v else None, f+"_per_call": ratio(sum(v), len(v)), f+"_max": max(v) if v else None})
    covered = [c for c in cs if c["cpu_us"] is not None]
    wall = sum(c["duration_us"] for c in covered)
    r["cpu_percent_of_wall"] = ratio(100*sum(c["cpu_us"] for c in covered), wall)
    r.update(cpu_available_count=len(covered) if n else None, cpu_wall_us=wall if n else None,
             cpu_coverage_percent=ratio(100*len(covered), n),
             cpu_wall_coverage_percent=ratio(100*wall, sum(c["duration_us"] for c in cs)))
    if not cs or not all("numeric_quality" in c for c in cs):
        for f in ("cpu_available_count", "cpu_wall_us", "cpu_coverage_percent", "cpu_wall_coverage_percent"):
            r[f] = None
    r.update({"memory_peak_"+k: v for k, v in stats([c["memory_peak"] for c in cs if c["memory_peak"] is not None]).items() if k != "sum"})
    return r


def chatty(cs, k, fast_us):
    n = len(cs)
    hit = [c for c in cs if c["db_count"] > k]
    fast = [c for c in cs if c["duration_us"] <= fast_us]
    fast_hit = [c for c in hit if c["duration_us"] <= fast_us]
    db = stats([c["db_count"] for c in cs])
    r = {"count": n, "db_count_sum": db["sum"], **{"db_per_call_"+p: db[p] for p in ("avg", "median", "p95", "max")},
         "linked_db_duration_us_sum": sum(c["db_duration_us"] for c in cs) if n else None,
         "linked_db_seconds_per_call": ratio(sum(c["db_duration_us"] for c in cs), n*1_000_000),
         "calls_with_zero_linked_db": sum(c["db_count"] == 0 for c in cs),
         "calls_above_threshold_count": len(hit), "call_share_denominator": n,
         "calls_above_threshold_percent": ratio(100*len(hit), n),
         "fast_call_count": len(fast), "fast_calls_above_threshold_count": len(fast_hit), "fast_call_share_denominator": len(fast),
         "fast_calls_above_threshold_percent": ratio(100*len(fast_hit), len(fast)),
         "chatty_db_count_sum": sum(c["db_count"] for c in hit) if n else None,
         "chatty_linked_db_duration_us_sum": sum(c["db_duration_us"] for c in hit) if n else None,
         "chatty_linked_db_seconds_per_call": ratio(sum(c["db_duration_us"] for c in hit), len(hit)*1_000_000)}
    for prefix, population in (("call_duration_us_", cs), ("chatty_call_duration_us_", hit)):
        dist = stats([c["duration_us"] for c in population])
        if n and not population:
            dist["sum"] = 0
        r.update({prefix+p: dist[p] for p in ("sum", "avg", "median", "p95", "max")})
    return r


def apdex_score(cs, t, failures):
    n = len(cs)
    result = {"count": n, "covered_call_count": n if t is not None else 0,
              "apdex_denominator": n if t is not None else 0,
              "confirmed_failure_count": sum(c["call_id"] in failures for c in cs),
              "business_outcome_unknown_count": sum(c["call_id"] not in failures for c in cs),
              "calls_with_linked_error_events": sum(c["error_count"] > 0 for c in cs)}
    names = "satisfied_count tolerating_count frustrated_count apdex_numerator_twice apdex latency_frustrated_count forced_frustrated_count".split()
    if not n or t is None:
        return {**result, **dict.fromkeys(names)}
    s = sum(c["duration_us"] <= t and c["call_id"] not in failures for c in cs)
    a = sum(t < c["duration_us"] <= 4*t and c["call_id"] not in failures for c in cs)
    result.update(satisfied_count=s, tolerating_count=a, frustrated_count=n-s-a, apdex_numerator_twice=2*s+a,
                  apdex=(2*s+a)/(2*n), latency_frustrated_count=sum(c["duration_us"] > 4*t for c in cs),
                  forced_frustrated_count=sum(c["duration_us"] <= 4*t and c["call_id"] in failures for c in cs))
    return result


class Audit:
    def __init__(self, analysis_dir, slices_dir):
        self.bundle = load_bundle(analysis_dir)
        self.root = slices_dir.resolve(strict=True)
        self.manifest = json.loads((self.root/"slice_manifest.json").read_text(encoding="utf-8"))
        self.cfg = normalize_config(self.manifest["configuration"])
        require(set(self.cfg["slices"]) == set(REGISTERED_SLICES), "requires a full 26-slice result")
        require(self.cfg["measurement_ids"] is None, "audit currently requires the full series, not a date filter")
        require(self.manifest["bundle_id"] == self.bundle.bundle_id, "bundle identity mismatch")
        self.groups = collections.defaultdict(list)
        self.pooled = collections.defaultdict(list)
        self.by_id = {c["call_id"]: c for c in self.bundle.calls}
        self.by_mid = collections.defaultdict(list)
        for c in self.bundle.calls:
            self.groups[(c["signature"], c["user"], c["measurement_id"])].append(c)
            self.pooled[(c["signature"], c["measurement_id"])].append(c)
            self.by_mid[c["measurement_id"]].append(c)
        require(all(c["start_timestamp"] for c in self.bundle.calls), "audit needs saved absolute CALL times")
        self.order = self.cfg["operations"]["measurement_order"] or sorted(self.by_mid, key=lambda m: min(c["start_timestamp"] for c in self.by_mid[m]))
        self.pos = {m: i for i, m in enumerate(self.order)}
        self.pairs = sorted({(s,u) for s,u,m in self.groups})
        self.ops = {k: operation(cs) for k,cs in self.groups.items()}
        self.empty = operation([])
        self.fast_us = int(Decimal(str(self.cfg["db_chatty"]["fast_call_max_seconds"]))*1_000_000)
        self.db_cache = {}
        self.row_counts = {}
        self.quality = {r["measurement_id"]: r for r in self.table("data_quality")}
        self.targets = {sig: cls for cls in self.cfg["apdex"]["classes"] for sig in cls["signatures"]}
        self.targets.update({r["signature"]: r for r in self.cfg["apdex"]["targets"]})
        self.failures = {r["call_id"] for r in self.cfg["apdex"]["confirmed_failures"]["calls"]}
        self.checks = list(self.bundle.checks)
        self.details = {}

    def table(self, name):
        path = self.root/(name+".csv")
        require(path.resolve(strict=True).parent == self.root, "slice path escapes result directory")
        descriptor = self.manifest["outputs"][name+".csv"]
        require(hashlib.sha256(path.read_bytes()).hexdigest() == descriptor["sha256"], name+" hash mismatch")
        count = 0
        for r in rows(path):
            count += 1
            yield r
        require(count == descriptor["row_count"], name+" row count mismatch")
        self.row_counts[name] = count

    def op(self, key):
        return self.ops.get(key, self.empty)

    def db(self, key, k):
        cache_key = (*key, k)
        if cache_key not in self.db_cache:
            self.db_cache[cache_key] = chatty(self.groups.get(key, []), k, self.fast_us)
        return self.db_cache[cache_key]

    def target_us(self, sig):
        return int(Decimal(str(self.targets[sig]["t_seconds"]))*1_000_000) if sig in self.targets else None

    def reference(self, sig, user, mid, basis):
        observed = [m for m in self.order if (sig,user,m) in self.groups]
        if basis == "series_baseline":
            return self.cfg["operations"]["series_baseline_measurement_id"] or self.order[0]
        if basis == "first_observation":
            return observed[0]
        if basis == "previous_measurement":
            return self.order[self.pos[mid]-1] if self.pos[mid] else None
        require(basis == "previous_observation", "unknown comparison basis")
        return next((m for m in reversed(observed) if self.pos[m] < self.pos[mid]), None)

    def base_comparison(self, r):
        s,u,m,b = (r[k] for k in ("signature","user","current_measurement_id","comparison_basis"))
        ref = self.reference(s,u,m,b)
        cur = self.op((s,u,m)); old = self.op((s,u,ref)) if ref else None
        check(r, {"reference_measurement_id": ref, "reference_count": old["count"] if old else None, "current_count": cur["count"]}, "comparison base")
        comparable = bool(old and old["count"] and cur["count"] and not (b=="first_observation" and self.pos[ref]>self.pos[m]))
        return (s,u,m), ref, comparable

    def numeric_changes(self, r, old, current, valid, metrics):
        for field in metrics:
            a = old.get(field) if old else None
            b = current.get(field)
            delta = b-a if valid and a is not None and b is not None else None
            check(r, {field+"_reference": a, field+"_current": b,
                      field+"_delta_absolute": delta, field+"_delta_percent": 100*delta/a if delta is not None and a else None}, "change")

    def history_and_comparisons(self):
        for table, pooled in (("operation_history",False),("operation_history_all_users",True)):
            seen = set(); n_total = 0
            for r in self.table(table):
                s,u,m = r["signature"],r["user"],r["measurement_id"]
                key = (s,m) if pooled else (s,u,m)
                require(key not in seen, "duplicate history group")
                seen.add(key)
                cs = self.pooled.get(key,[]) if pooled else self.groups.get(key,[])
                check(r,operation(cs),table)
                require(sorted(json.loads(r["call_ids"])) == sorted(c["call_id"] for c in cs), "CALL membership")
                require(r["observation_status"] == ("observed" if cs else "not_observed"), "absence state")
                n_total += int(r["count"])
            expected = len(self.pooled_signature_set()) if pooled else len(self.pairs)
            require(len(seen)==expected*len(self.order), "incomplete history grid")
            require(n_total == len(self.bundle.calls), "history double counting or lost CALLs")
        missing_refs = zero_refs = small = different_previous = 0
        for r in self.table("measurement_comparisons"):
            key, ref, valid = self.base_comparison(r)
            old = self.op((*key[:2],ref)) if ref else None
            self.numeric_changes(r, old, self.op(key), valid, [f for f in self.empty if f!="count"])
            missing_refs += bool(old and not old["count"])
            zero_refs += len(json.loads(r["percent_undefined_zero_reference_metrics"]))
            small += r["sample_size_status"]=="below_configured_minimum"
            if r["comparison_basis"]=="previous_observation" and key in self.groups:
                different_previous += ref is not None and ref!=self.reference(*key,"previous_measurement")
        for r in self.table("comparability"):
            key,ref,valid = self.base_comparison(r)
            unknown=json.loads(r["unknown_parameters"])
            require({"role","document","parameters","data_volume","cold_warm","concurrent_load","application_version"} <= set(unknown), "unknown parameters omitted")
            require(r["user_match"] == ("true" if valid and key[1] not in UNKNOWN_USERS else ""), "user comparability overclaimed")
        self.details.update(missing_reference_rows=missing_refs, undefined_zero_reference_metric_deltas=zero_refs,
                            small_sample_comparison_rows=small, gaps_with_distinct_previous_bases=different_previous)
        self.checks += ["independent_CALL_metrics_all_users_and_same_user_no_double_count", "independent_median_nearest_rank_p95_p99", "four_reference_bases_gaps_zero_bases_unknown_parameters"]

    def pooled_signature_set(self):
        return {s for s,m in self.pooled}

    def db_checks(self):
        for r in self.table("db_chatty"):
            key=tuple(r[k] for k in ("signature","user","measurement_id")); k=int(r["threshold_db_events"])
            v=self.db(key,k); check(r,v,"DB group")
            check(r,{"group_mean_above_threshold": v["db_count_sum"]>k*v["count"] if v["count"] else None},"mean flag")
        for name,fast_only in (("db_chatty_calls",False),("db_chatty_fast_calls",True)):
            seen=set()
            for r in self.table(name):
                cid=int(r["call_id"]); require(cid not in seen,"duplicate DB CALL"); seen.add(cid)
                c=self.by_id[cid]; ks=[k for k in self.cfg["db_chatty"]["thresholds"] if c["db_count"]>k]
                check(r,{"thresholds_exceeded":ks,"linked_db_count":c["db_count"],"linked_db_duration_us":c["db_duration_us"],"duration_us":c["duration_us"],"is_fast_call":c["duration_us"]<=self.fast_us},name)
            expected={c["call_id"] for c in self.bundle.calls if c["db_count"]>min(self.cfg["db_chatty"]["thresholds"]) and (not fast_only or c["duration_us"]<=self.fast_us)}
            require(seen==expected,"DB CALL coverage")
        for r in self.table("db_chatty_duration"):
            key=tuple(r[k] for k in ("signature","user","measurement_id")); k=int(r["threshold_db_events"])
            lo=int(r["duration_lower_us_exclusive"]) if r["duration_lower_us_exclusive"] else None
            hi=int(r["duration_upper_us_inclusive"]) if r["duration_upper_us_inclusive"] else None
            cs=[c for c in self.groups[key] if (lo is None or c["duration_us"]>lo) and (hi is None or c["duration_us"]<=hi)]
            hit=[c for c in cs if c["db_count"]>k]; all_hits=sum(c["db_count"]>k for c in self.groups[key])
            check(r,{"band_call_count":len(cs),"band_calls_above_threshold_count":len(hit),"within_band_call_denominator":len(cs),
                     "within_band_above_threshold_percent":ratio(100*len(hit),len(cs)),"group_chatty_call_denominator":all_hits,
                     "share_of_group_chatty_calls_percent":ratio(100*len(hit),all_hits),
                     "band_call_duration_us_sum":sum(c["duration_us"] for c in cs),"band_linked_db_duration_us_sum":sum(c["db_duration_us"] for c in cs)},"duration band")
        for r in self.table("db_chatty_coverage"):
            cs=[c for m in json.loads(r["measurement_ids"]) for c in self.by_mid[m]]; k=int(r["threshold_db_events"])
            hit=[c for c in cs if c["db_count"]>k]; fast=[c for c in cs if c["duration_us"]<=self.fast_us]
            ops={c["signature"] for c in cs}; hit_ops={c["signature"] for c in hit}
            users={c["user"] for c in cs if c["user"] not in UNKNOWN_USERS}; hit_users={c["user"] for c in hit if c["user"] not in UNKNOWN_USERS}
            check(r,{"total_call_count":len(cs),"chatty_call_count":len(hit),"call_share_denominator":len(cs),"chatty_call_percent":ratio(100*len(hit),len(cs)),
                "observed_operation_count":len(ops),"affected_operation_count":len(hit_ops),"operation_share_denominator":len(ops),"affected_operation_percent":ratio(100*len(hit_ops),len(ops)),
                "observed_known_user_count":len(users),"affected_known_user_count":len(hit_users),"known_user_share_denominator":len(users),"affected_known_user_percent":ratio(100*len(hit_users),len(users)),
                "fast_call_share_denominator":len(fast),"fast_chatty_call_percent":ratio(100*sum(c["db_count"]>k for c in fast),len(fast))},"DB coverage units")
        for r in self.table("db_chatty_changes"):
            key,ref,valid=self.base_comparison(r); k=int(r["threshold_db_events"])
            current=self.db(key,k); old=self.db((*key[:2],ref),k) if ref else None
            self.numeric_changes(r,old,current,valid,[f for f in current if f!="count"])
        self.checks += ["independent_group_mean_vs_actual_CALL_hits", "independent_DB_distributions_denominators_scope_units_and_changes"]

    def apdex_checks(self):
        for r in self.table("apdex"):
            key=tuple(r[k] for k in ("signature","user","measurement_id")); cs=self.groups.get(key,[]); t=self.target_us(key[0])
            check(r,{**apdex_score(cs,t,self.failures),"t_us":t,"small_sample_warning":0<len(cs)<self.cfg["apdex"]["min_call_count"]},"APDEX group")
        covered_ids=set()
        for r in self.table("apdex_calls"):
            cid=int(r["call_id"]); require(cid not in covered_ids,"duplicate APDEX CALL"); covered_ids.add(cid)
            c=self.by_id[cid]; t=self.target_us(c["signature"])
            require(t is not None,"uncovered APDEX CALL classified")
            category="frustrated" if cid in self.failures or c["duration_us"]>4*t else ("tolerating" if c["duration_us"]>t else "satisfied")
            require(r["category"]==category,"APDEX CALL category")
        require(covered_ids=={c["call_id"] for c in self.bundle.calls if c["signature"] in self.targets},"APDEX coverage population")
        uncovered={(r["signature"],r["user"],r["measurement_id"]) for r in self.table("apdex_uncovered")}
        require(uncovered=={k for k in self.groups if k[0] not in self.targets},"uncovered APDEX groups")
        for r in self.table("apdex_coverage"):
            cs=[c for m in json.loads(r["measurement_ids"]) for c in self.by_mid[m]]
            covered=[c for c in cs if c["signature"] in self.targets]
            ops={c["signature"] for c in cs}; scored_ops={c["signature"] for c in covered}
            check(r,{"total_call_count":len(cs),"covered_call_count":len(covered),"uncovered_call_count":len(cs)-len(covered),"call_share_denominator":len(cs),
                     "covered_call_percent":ratio(100*len(covered),len(cs)),"observed_operation_count":len(ops),"covered_operation_count":len(scored_ops),"operation_share_denominator":len(ops),"covered_operation_percent":ratio(100*len(scored_ops),len(ops))},"APDEX coverage")
        composition=collections.defaultdict(list)
        for r in self.table("apdex_composition"):
            composition[r["overall_id"]].append(r)
        for r in self.table("apdex_overall"):
            mids=json.loads(r["measurement_ids"])
            cs=[c for m in mids for c in self.by_mid[m] if self.targets.get(c["signature"],{}).get("status")==r["target_status"]]
            n=len(cs); score=collections.Counter()
            for c in cs:
                score.update({k:v for k,v in apdex_score([c],self.target_us(c["signature"]),self.failures).items() if k!="apdex"})
            fields={k:score[k] for k in ("count","apdex_denominator","satisfied_count","tolerating_count","frustrated_count","apdex_numerator_twice")}
            if not n:
                fields.update(dict.fromkeys(("satisfied_count","tolerating_count","frustrated_count","apdex_numerator_twice")))
            fields["apdex"]=ratio(score["apdex_numerator_twice"],2*n)
            check(r,fields,"overall APDEX direct CALLs")
            components=composition[r["overall_id"]]
            require(sum(int(x["call_count"]) for x in components)==n,"composition denominator")
            if n:
                require(math.isclose(sum(float(x["contribution_to_overall_apdex"]) for x in components),fields["apdex"],abs_tol=1e-12),"composition contributions")
                require(math.isclose(sum(float(x["call_weight_percent"]) for x in components),100,abs_tol=1e-9),"composition weights")
        for r in self.table("apdex_changes"):
            key,ref,valid=self.base_comparison(r); t=self.target_us(key[0])
            old=apdex_score(self.groups.get((*key[:2],ref),[]),t,self.failures) if ref else None
            current=apdex_score(self.groups.get(key,[]),t,self.failures)
            metrics="apdex satisfied_count tolerating_count frustrated_count confirmed_failure_count forced_frustrated_count".split()
            self.numeric_changes(r,old,current,valid and t is not None and key[1] not in UNKNOWN_USERS,metrics)
        self.details.update(apdex_covered_CALLs=len(covered_ids),apdex_uncovered_CALLs=len(self.bundle.calls)-len(covered_ids))
        self.checks += ["independent_APDEX_counts_boundaries_coverage_changes_and_composition"]

    def problem_checks(self):
        from slice_problem_config import METRICS  # Only field names, never detection/calculation helpers.
        rules={r["rule_id"]:r for r in self.cfg["problems"]["rules"]}
        cache={}
        def evaluate(rule,key):
            ck=(rule["rule_id"],*key)
            if ck in cache:
                return cache[ck]
            cs=self.groups.get(key,[]); n=len(cs); cat=METRICS[rule["metric"]]
            source=self.op(key) if cat["source"]=="operation_history" else (self.db(key,rule["db_events_threshold"]) if cat["source"]=="db_chatty" else apdex_score(cs,self.target_us(key[0]),self.failures))
            v=source[cat["field"]] if n else None
            if rule["metric"]=="apdex.deficit" and v is not None:
                v=(2*n-source["apdex_numerator_twice"])/(2*n)
            quality=self.quality[key[2]]
            good=v is not None and n>=rule["min_call_count"] and key[1] not in UNKNOWN_USERS
            if rule["require_clean_sources"]:
                good=good and quality["recorded_source_health"]=="no_recorded_related_capture_problem" and not int(quality["calls_from_partial_sources"])
            for kind in ("count","duration"):
                gate=rule["min_db_linked_"+kind+"_percent"]
                actual=quality["db_linked_"+kind+"_percent"]
                if gate is not None:
                    good=good and actual!="" and float(actual)>=gate
            breach=None if v is None else (v>rule["threshold"] if rule["operator"]==">" else v>=rule["threshold"])
            cache[ck]=(n,v,bool(good),breach)
            return cache[ck]
        expected={}
        for rule in rules.values():
            for s,u in self.pairs:
                if rule["signatures"] is not None and s not in rule["signatures"] or rule["users"] is not None and u not in rule["users"]:
                    continue
                first=next((m for m in self.order if evaluate(rule,(s,u,m))[3] is True),None)
                if first:
                    expected[(rule["rule_id"],s,u)]=first
        registry=list(self.table("problem_registry")); history=list(self.table("problem_history"))
        require(len(registry)==len(expected) and {(r["rule_id"],r["signature"],r["user"]) for r in registry}==set(expected),"problem discovery population")
        require(len({r["problem_id"] for r in registry})==len(registry),"duplicate problem identity")
        grouped=collections.defaultdict(list)
        improved=set(); worsened=set()
        for r in history:
            rule=rules[r["rule_id"]]; key=tuple(r[k] for k in ("signature","user","measurement_id"))
            s,u,m=key; first=expected[(rule["rule_id"],s,u)]; n,v,good,breach=evaluate(rule,key)
            check(r,{"count":n,"value":v,"eligible_for_comparison":good,"threshold_breached":breach,"first_problem_measurement_id":first},"problem value")
            status="не наблюдалось" if not n else ("недостаточно данных" if not good else ("порог превышен" if breach else "ниже порога в наблюдениях"))
            require(r["threshold_status"]==status,"problem threshold status")
            previous=next((pm for pm in reversed(self.order[:self.pos[m]]) if evaluate(rule,(s,u,pm))[2]),None)
            for basis,ref in (("first_problem",first),("previous_comparable",previous)):
                rn,rv,rg,_=evaluate(rule,(s,u,ref)) if ref else (None,None,False,None)
                delta=v-rv if good and rg else None
                check(r,{basis+"_reference_measurement_id":ref,basis+"_reference_count":rn,basis+"_reference_value":rv,
                         basis+"_delta_absolute":delta,basis+"_delta_percent":100*delta/rv if delta is not None and rv else None},"problem delta")
                if delta is not None and delta<0: improved.add((r["history_row_id"],basis))
                if delta is not None and delta>0: worsened.add((r["history_row_id"],basis))
            grouped[r["problem_id"]].append(r)
        for r in registry:
            hs=grouped[r["problem_id"]]
            require([h["measurement_id"] for h in hs]==self.order[self.pos[r["first_problem_measurement_id"]]:],"problem missing history dates")
            require(all(r[k]==hs[-1][k] for k in hs[-1]),"registry not latest snapshot")
        for table,expected_transitions in (("problem_improved",improved),("problem_worsened",worsened)):
            actual=list(self.table(table))
            require(len(actual)==len(expected_transitions) and {(r["history_row_id"],r["comparison_basis"]) for r in actual}==expected_transitions,"transition extract")
        for table,ids in (("problem_new",{r["problem_id"] for r in registry}),
                          ("problem_persisting",{r["problem_id"] for r in registry if r["threshold_status"]=="порог превышен"}),
                          ("problem_unchecked",{r["problem_id"] for r in registry if r["first_problem_measurement_id"]!=self.order[-1] and r["eligible_for_comparison"]=="false"})):
            actual=list(self.table(table))
            require(len(actual)==len(ids) and {r["problem_id"] for r in actual}==ids,"problem extract")
        for r in self.table("problem_rule_coverage"):
            rule=rules[r["rule_id"]]; m=r["measurement_id"]
            pairs=[(s,u) for s,u in self.pairs if (rule["signatures"] is None or s in rule["signatures"]) and (rule["users"] is None or u in rule["users"])]
            es=[evaluate(rule,(s,u,m)) for s,u in pairs]
            check(r,{"observed_call_count":sum(e[0] for e in es),"evaluable_cohort_count":sum(e[2] for e in es),
                     "raw_threshold_breach_cohort_count":sum(e[3] is True for e in es)},"rule coverage")
        self.details.update(problem_cards=len(registry),problem_history_rows=len(history),problem_discoveries_by_measurement=dict(collections.Counter(r["first_problem_measurement_id"] for r in registry)))
        self.checks += ["independent_numeric_problem_discovery_history_deltas_and_five_extracts"]

    def run(self):
        self.history_and_comparisons(); self.db_checks(); self.apdex_checks(); self.problem_checks()
        for m, r in self.quality.items():
            cs=self.by_mid[m]
            check(r,{"call_count":len(cs),"operation_signature_count":len({c["signature"] for c in cs}),"operation_user_count":len({(c["signature"],c["user"]) for c in cs})},"quality population")
            for f in ("cpu_us","in_bytes","out_bytes","memory_peak"):
                current = self.bundle.manifest["schema_version"] in {"1.3", "1.4", "1.5", "1.6"}
                entry = json.loads(r["metric_availability"])[f]
                require(entry["raw_missing_vs_zero_distinguishable"] is current,"numeric quality provenance mismatch")
                if current:
                    q = entry["numeric_quality"]
                    available = [c[f] for c in cs if c[f] is not None]
                    require(q["available_count"] == q["mean_denominator"] == len(available), "numeric mean denominator mismatch")
                    require(q["sum_known"] == (sum(available) if available else None), "numeric available sum mismatch")
        require(set(self.row_counts)==set(REGISTERED_SLICES),"not all slices audited")
        self.bundle.assert_unchanged()
        totals={f:(sum(c[f] for c in self.bundle.calls if c[f] is not None) if any(c[f] is not None for c in self.bundle.calls) else None) for f in ("duration_us","db_count","db_duration_us","cpu_us","in_bytes","out_bytes")}
        return {"status":"PASS","audit_version":AUDIT_VERSION,"bundle_id":self.bundle.bundle_id,
                "calculator_version":self.manifest["calculator_version"],"slice_schema_version":self.manifest["slice_schema_version"],
                "input_files":self.bundle.input_files,"input_files_unchanged":True,"source_analysis_complete":self.bundle.manifest["analysis_complete"],
                "checks":self.checks,"CALL_count":len(self.bundle.calls),"operation_signatures":len(self.pooled_signature_set()),"operation_user_pairs":len(self.pairs),
                "measurement_order":self.order,"row_counts":self.row_counts,"CALL_population_totals":totals,"details":self.details,
                "scope":"saved_bundle_and_full_slice_result_only; no_raw_TJ_access; sums_not_exclusive_wall_time",
                "not_checked_here":["raw_capture_completeness","per_CALL_DB_linkage_correctness","business_outcomes","code_change_causality","runtime_reproducibility_requires_separate_repeat_run"]}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analysis-dir",type=Path,required=True)
    parser.add_argument("--slices-dir",type=Path,required=True)
    args=parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")
    try:
        result=Audit(args.analysis_dir,args.slices_dir).run()
    except (SliceError,OSError,KeyError,ValueError,csv.Error) as exc:
        print(json.dumps({"status":"FAIL","error":str(exc)},ensure_ascii=False)); return 2
    print(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2)); return 0


if __name__=="__main__":
    raise SystemExit(main())
