from pathlib import Path
import hashlib
import json
import re

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

ROOT = Path(r"C:\Users\ENCO\Documents\mission1\security_project")
DATA = ROOT / "eda_security_data_clean_260915_01"
LDAP = Path(r"C:\Users\ENCO\Downloads\data\LDAP")
OUT = ROOT / "06_산출물"
OUT.mkdir(parents=True, exist_ok=True)


def anon(value: str) -> str:
    return "usr_" + hashlib.sha256(str(value).encode()).hexdigest()[:12]


def read_ldap():
    parts = []
    for p in sorted(LDAP.glob("*.csv")):
        x = pd.read_csv(p, usecols=["user_id", "email"], dtype=str)
        x["month"] = p.stem
        x["email"] = x["email"].str.strip().str.lower()
        parts.append(x)
    x = pd.concat(parts, ignore_index=True).drop_duplicates(["month", "user_id", "email"])
    return set(map(tuple, x[["month", "user_id", "email"]].itertuples(index=False, name=None)))


def addresses(text):
    if pd.isna(text):
        return []
    return [a.strip().lower() for a in str(text).split(";") if "@" in a]


def aggregate_email(valid_senders):
    rows = []
    evidence = []
    cols = ["id", "date", "user", "pc", "to", "cc", "bcc", "from", "size", "attachments"]
    for ch in pd.read_csv(DATA / "email.csv", usecols=cols, chunksize=100_000):
        ch["dt"] = pd.to_datetime(ch["date"], errors="coerce")
        ch = ch[ch["dt"].notna()].copy()
        ch["month"] = ch["dt"].dt.strftime("%Y-%m")
        ch["from_norm"] = ch["from"].fillna("").str.strip().str.lower()
        ok = [(m, u, f) in valid_senders for m, u, f in zip(ch.month, ch.user, ch.from_norm)]
        ch = ch[np.asarray(ok)].copy()
        if ch.empty:
            continue
        recips = []
        domains = []
        ext_bcc = []
        for to, cc, bcc in zip(ch["to"], ch["cc"], ch["bcc"]):
            aa = addresses(to) + addresses(cc) + addresses(bcc)
            ext = [a for a in aa if a.rsplit("@", 1)[-1] != "dtaa.com"]
            recips.append(len(ext))
            domains.append(len(set(a.rsplit("@", 1)[-1] for a in ext)))
            ext_bcc.append(sum(a.rsplit("@", 1)[-1] != "dtaa.com" for a in addresses(bcc)))
        ch["ext_recipients"] = recips
        ch["ext_domains"] = domains
        ch["ext_bcc"] = ext_bcc
        ch["external"] = (ch["ext_recipients"] > 0).astype(int)
        ch["attachments"] = pd.to_numeric(ch["attachments"], errors="coerce").fillna(0)
        ch["size"] = pd.to_numeric(ch["size"], errors="coerce").fillna(0)
        ch["external_attach"] = ((ch.external == 1) & (ch.attachments > 0)).astype(int)
        ch["external_attachment_units"] = ch["attachments"].where(ch.external.eq(1), 0)
        ch["external_size"] = ch["size"].where(ch.external.eq(1), 0)
        ch["offhours_external"] = ((ch.external == 1) & ((ch.dt.dt.weekday >= 5) | (ch.dt.dt.hour < 8) | (ch.dt.dt.hour >= 19))).astype(int)
        ch["day"] = ch["dt"].dt.floor("D")
        g = ch.groupby(["user", "day"], sort=False).agg(
            email_count=("id", "size"), external_email_count=("external", "sum"),
            external_attach_count=("external_attach", "sum"), attachment_count=("external_attachment_units", "sum"),
            external_size_sum=("external_size", "sum"), external_size_max=("external_size", "max"),
            external_recipient_count=("ext_recipients", "sum"), external_domain_count=("ext_domains", "sum"),
            external_bcc_count=("ext_bcc", "sum"), offhours_external_count=("offhours_external", "sum")
        ).reset_index()
        rows.append(g)
        ev = ch[ch.external.eq(1)].sort_values("dt").groupby(["user", "day"], sort=False).agg(
            email_event_ids=("id", lambda s: "|".join(s.astype(str).head(5))),
            email_pcs=("pc", lambda s: "|".join(pd.unique(s.astype(str))[:3]))
        ).reset_index()
        evidence.append(ev)
    agg = pd.concat(rows).groupby(["user", "day"], as_index=False).sum(numeric_only=True)
    ev = pd.concat(evidence).groupby(["user", "day"], as_index=False).agg({"email_event_ids":"first", "email_pcs":"first"})
    return agg, ev


def aggregate_simple(name, fields):
    rows = []
    evs = []
    for ch in pd.read_csv(DATA / f"{name}.csv", usecols=["id", "date", "user"] + fields, chunksize=150_000):
        ch["dt"] = pd.to_datetime(ch["date"], errors="coerce")
        ch = ch[ch.dt.notna()].copy()
        ch["day"] = ch.dt.dt.floor("D")
        g = ch.groupby(["user", "day"], sort=False).agg(**{f"{name}_count":("id", "size")}).reset_index()
        rows.append(g)
        evs.append(ch.groupby(["user", "day"], sort=False)["id"].first().reset_index(name=f"{name}_event_ids"))
    agg = pd.concat(rows).groupby(["user", "day"], as_index=False).sum(numeric_only=True)
    ev = pd.concat(evs).groupby(["user", "day"], as_index=False).first()
    return agg, ev


def add_personal_z(df, columns):
    df = df.sort_values(["user", "day"]).copy()
    for c in columns:
        med = df.groupby("user")[c].transform("median")
        q1 = df.groupby("user")[c].transform(lambda s: s.quantile(.25))
        q3 = df.groupby("user")[c].transform(lambda s: s.quantile(.75))
        scale = (q3 - q1) / 1.349
        z = (df[c] - med) / scale.replace(0, np.nan)
        z = z.where(scale.ne(0), np.where(df[c] > med, 6, 0))
        df[c + "_personal_z"] = np.clip(z.fillna(0), -10, 10)
    return df


def main():
    valid = read_ldap()
    email, email_ev = aggregate_email(valid)
    frames, evframes = [email], [email_ev]
    for name, fields in [("file", ["pc"]), ("device", ["pc", "activity"]), ("logon", ["pc", "activity"]), ("http", ["pc"])]:
        a, e = aggregate_simple(name, fields)
        frames.append(a); evframes.append(e)
    all_keys = pd.concat([x[["user", "day"]] for x in frames]).drop_duplicates()
    df = all_keys
    for x in frames:
        df = df.merge(x, on=["user", "day"], how="left")
    numeric = [c for c in df.columns if c not in ["user", "day"]]
    df[numeric] = df[numeric].fillna(0)
    base_cols = ["external_email_count", "external_attach_count", "attachment_count", "external_size_sum", "external_size_max", "external_recipient_count", "external_domain_count", "external_bcc_count", "offhours_external_count", "file_count", "device_count", "logon_count", "http_count"]
    df = add_personal_z(df, base_cols)
    model_cols = base_cols + [c + "_personal_z" for c in base_cols]
    X = df[model_cols].copy()
    for c in base_cols:
        X[c] = np.log1p(X[c].clip(lower=0))
    X = RobustScaler(quantile_range=(10, 90)).fit_transform(X)
    model = IsolationForest(n_estimators=300, contamination=0.01, random_state=42, n_jobs=-1)
    pred = model.fit_predict(X)
    raw = -model.score_samples(X)
    df["anomaly_score"] = 100 * (raw - raw.min()) / (raw.max() - raw.min())
    df["model_anomaly"] = pred == -1
    df["rule_s3_candidate"] = (df.file_count_personal_z >= 3) & (df.external_attach_count > 0) & ((df.external_size_max_personal_z >= 3) | (df.attachment_count >= 2))
    df["rule_multisignal"] = ((df.external_email_count_personal_z >= 3).astype(int) + (df.attachment_count_personal_z >= 3).astype(int) + (df.offhours_external_count > 0).astype(int) + (df.file_count_personal_z >= 3).astype(int)) >= 2
    df["evidence_strength"] = np.select([df.rule_s3_candidate & df.model_anomaly, df.rule_multisignal & df.model_anomaly, df.model_anomaly], ["MODEL+S3_RULE", "MODEL+MULTI_SIGNAL", "MODEL_ONLY"], default="RULE_OR_GENERAL")
    for ev in evframes:
        df = df.merge(ev, on=["user", "day"], how="left")
    df["anon_user"] = df.user.map(anon)
    ranked_days = df[df.model_anomaly].sort_values(["rule_s3_candidate", "rule_multisignal", "anomaly_score"], ascending=False)
    user = df.groupby("user").agg(max_anomaly_score=("anomaly_score", "max"), anomalous_days=("model_anomaly", "sum"), s3_rule_days=("rule_s3_candidate", "sum"), multisignal_days=("rule_multisignal", "sum"), first_day=("day", "min"), last_day=("day", "max")).reset_index()
    user["priority_score"] = user.max_anomaly_score + np.minimum(user.anomalous_days, 10) + 15 * (user.s3_rule_days > 0) + 5 * np.minimum(user.s3_rule_days, 3)
    user = user.sort_values(["s3_rule_days", "priority_score", "max_anomaly_score"], ascending=False)
    user["anon_user"] = user.user.map(anon)
    safe_day_cols = [c for c in ranked_days.columns if c != "user"]
    ranked_days[safe_day_cols].to_csv(OUT / "anomalous_user_days.csv", index=False, encoding="utf-8-sig")
    user.drop(columns="user").to_csv(OUT / "risky_users.csv", index=False, encoding="utf-8-sig")
    top = ranked_days.head(30)
    summary = {
        "rows_user_day": int(len(df)), "users": int(df.user.nunique()),
        "date_min": str(df.day.min()), "date_max": str(df.day.max()),
        "model_anomalous_days": int(df.model_anomaly.sum()), "model_anomalous_users": int(df.loc[df.model_anomaly, "user"].nunique()),
        "s3_rule_days": int(df.rule_s3_candidate.sum()), "s3_rule_users": int(df.loc[df.rule_s3_candidate, "user"].nunique()),
        "model_and_s3_days": int((df.model_anomaly & df.rule_s3_candidate).sum()),
        "verified_email_events": int(df.email_count.sum()), "external_email_events": int(df.external_email_count.sum()),
        "model": {"name":"IsolationForest", "n_estimators":300, "contamination":0.01, "random_state":42, "features":model_cols}
    }
    (OUT / "analysis_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    top.drop(columns="user").to_csv(OUT / "top_evidence.csv", index=False, encoding="utf-8-sig")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
