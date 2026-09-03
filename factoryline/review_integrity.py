"""Three fail-closed senior-review controls: intent/diff, freshness, and policy ownership."""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib, json, os, tempfile
from pathlib import Path
from typing import Any
from .revenueforge import AUTHORITY, RevenueForgeError

def _sha(v: object)->str:return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def _read(root:Path,path:Path)->tuple[dict[str,Any],Path]:
 p=(path.resolve() if path.is_absolute() else (root/path).resolve())
 try:p.relative_to(root)
 except ValueError as e:raise RevenueForgeError("REVIEW_INTEGRITY_PATH_REJECTED","paths must remain inside the workspace") from e
 try:v=json.loads(p.read_text(encoding="utf-8"))
 except (OSError,json.JSONDecodeError) as e:raise RevenueForgeError("REVIEW_INTEGRITY_INPUT_INVALID","inputs must be JSON objects") from e
 if not isinstance(v,dict):raise RevenueForgeError("REVIEW_INTEGRITY_INPUT_INVALID","inputs must be JSON objects")
 return v,p
def _write(root:Path,path:Path,core:dict[str,Any])->dict[str,Any]:
 target=(path.resolve() if path.is_absolute() else (root/path).resolve());target.parent.mkdir(parents=True,exist_ok=True);result={**core,"receipt_sha256":_sha(core)};fd,tmp=tempfile.mkstemp(dir=str(target.parent),prefix=".receipt.")
 try:
  with os.fdopen(fd,"w",encoding="utf-8") as f:json.dump(result,f,indent=2,sort_keys=True);f.write("\n")
  os.replace(tmp,target)
 finally:
  if os.path.exists(tmp):os.unlink(tmp)
 return {**result,"path":target.relative_to(root).as_posix()}
def _base(kind:str,ok:bool,findings:list[str],sources:dict[str,str])->dict[str,Any]:
 return {"schema":f"factory.review-integrity.{kind}-receipt.v1","marker":f"REVIEW_{kind.upper()}_READY" if ok else f"REVIEW_{kind.upper()}_BLOCKED","ok":ok,"findings":findings,"sources":sources,"authority":{**AUTHORITY,"execution":False,"release":False,"policy_override":False},"claim_boundary":"Local deterministic metadata validation only; not semantic code understanding, environment execution, signature verification, or release approval."}

def _instant(value: object) -> datetime | None:
 """Parse a timezone-aware ISO-8601 instant or return None for ambiguous timestamp input."""
 if not isinstance(value, str) or "T" not in value:
  return None
 try:
  parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
 except ValueError:
  return None
 if parsed.tzinfo is None:
  return None
 return parsed.astimezone(timezone.utc)

def verify_intent_diff(root:Path,contract_path:Path,diff_path:Path,out:Path)->dict[str,Any]:
 """Fail closed when a declared change exceeds approved intent or forbidden behavior."""
 root=Path(root).resolve();c,cp=_read(root,contract_path);d,dp=_read(root,diff_path);find=[]
 if set(c)!={"schema","approved_paths","forbidden_terms","approval"} or c.get("schema")!="factory.intent-diff-contract.v1" or not isinstance(c.get("approved_paths"),list):raise RevenueForgeError("INTENT_DIFF_CONTRACT_INVALID","contract needs approved_paths, forbidden_terms, and human/trusted approval")
 if not isinstance(c["approval"],dict) or c["approval"].get("origin") not in {"human_confirmed","trusted_source"}:find.append("E_INTENT_AUTHORITY_MISSING")
 if set(d)!={"schema","base_sha","head_sha","changed_paths","added_text"} or d.get("schema")!="factory.diff-manifest.v1" or not isinstance(d.get("changed_paths"),list) or not isinstance(d.get("added_text"),str):raise RevenueForgeError("INTENT_DIFF_MANIFEST_INVALID","diff manifest must be explicit and bounded")
 for p in d["changed_paths"]:
  if not isinstance(p,str) or not any(p==scope or p.startswith(scope.rstrip("/")+"/") for scope in c["approved_paths"]):find.append("E_INTENT_SCOPE_DRIFT:"+str(p))
 for term in c.get("forbidden_terms",[]):
  if isinstance(term,str) and term and term.lower() in d["added_text"].lower():find.append("E_INTENT_FORBIDDEN_BEHAVIOR:"+term)
 core=_base("intent_diff",not find,find,{"contract":cp.relative_to(root).as_posix(),"diff":dp.relative_to(root).as_posix()});core.update({"action_summary":"Compare a declared diff against human-approved scope and forbidden behaviors before review promotion.","base_sha":d["base_sha"],"head_sha":d["head_sha"],"repair_plan":["Remove or separately approve the out-of-scope path or forbidden behavior." for _ in find]});return _write(root,out,core)

def verify_receipt_freshness(root:Path,manifest_path:Path,out:Path)->dict[str,Any]:
 """Reject release receipts that are stale, replayed, expired, or environment mismatched."""
 root=Path(root).resolve();m,mp=_read(root,manifest_path);find=[]
 if set(m)!={"schema","current_commit","environment_sha256","now","receipts"} or m.get("schema")!="factory.receipt-freshness-manifest.v1" or not isinstance(m.get("receipts"),list):raise RevenueForgeError("RECEIPT_FRESHNESS_MANIFEST_INVALID","manifest needs current commit, environment digest, time, and receipts")
 seen=set()
 for r in m["receipts"]:
  if not isinstance(r,dict) or set(r)!={"id","commit","environment_sha256","expires_at","nonce"}:find.append("E_RECEIPT_METADATA_LOOSE");continue
  if r["id"] in seen:find.append("E_RECEIPT_REPLAY:"+str(r["id"]));continue
  seen.add(r["id"])
  if r["commit"]!=m["current_commit"]:find.append("E_RECEIPT_STALE_COMMIT:"+str(r["id"]))
  if r["environment_sha256"]!=m["environment_sha256"]:find.append("E_RECEIPT_ENVIRONMENT_DRIFT:"+str(r["id"]))
  expires_at, now = _instant(r["expires_at"]), _instant(m["now"])
  if not isinstance(r["nonce"],str) or not r["nonce"] or expires_at is None or now is None or expires_at<=now:find.append("E_RECEIPT_EXPIRED:"+str(r["id"]))
 core=_base("freshness",not find,find,{"manifest":mp.relative_to(root).as_posix()});core.update({"action_summary":"Reject stale, replayed, expired, or environment-mismatched release-critical receipts.","receipt_count":len(m["receipts"]),"repair_plan":["Re-run the exact gate for the current commit and environment with a new expiry and nonce." for _ in find]});return _write(root,out,core)

def verify_policy_pack(root:Path,pack_path:Path,out:Path)->dict[str,Any]:
 """Verify that a selected team policy pack is explicit, versioned, and human owned."""
 root=Path(root).resolve();p,pp=_read(root,pack_path);find=[]
 if set(p)!={"schema","owner","version","approval","rules"} or p.get("schema")!="factory.team-policy-pack.v1" or not isinstance(p.get("rules"),list):raise RevenueForgeError("TEAM_POLICY_PACK_INVALID","pack needs human-owned versioned rules")
 if not isinstance(p.get("owner"),str) or not p["owner"].strip() or not isinstance(p.get("version"),str) or not p["version"].strip():find.append("E_POLICY_OWNER_OR_VERSION_MISSING")
 if not isinstance(p.get("approval"),dict) or p["approval"].get("origin") not in {"human_confirmed","trusted_source"}:find.append("E_POLICY_AGENT_OWNED")
 if not p["rules"] or not all(isinstance(x,dict) and set(x)=={"id","requirement","gate"} and all(isinstance(x[k],str) and x[k] for k in x) for x in p["rules"]):find.append("E_POLICY_RULE_LOOSE")
 core=_base("policy_pack",not find,find,{"pack":pp.relative_to(root).as_posix()});core.update({"action_summary":"Verify a human-owned, versioned team policy pack before it is selected as a review baseline.","owner":p.get("owner"),"version":p.get("version"),"rule_count":len(p["rules"]),"repair_plan":["Have the designated human/trusted owner approve explicit rule-to-gate mappings." for _ in find]});return _write(root,out,core)
