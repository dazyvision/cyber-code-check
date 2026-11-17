"""Structures partagées par les analyseurs statiques ; jamais de code cible exécuté."""

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class SourceFile:
    path: str
    text: str
    sha256: str
    size: int


def finding(rule_id, file, line, title, severity, confidence, evidence,
            recommendation, source_url, category):
    """Evidence doit décrire le motif, jamais recopier une valeur de secret.

    Les analyseurs utilisent uniquement des messages de preuve fixes ou des
    métadonnées expurgées ; aucun extrait de la ligne source n'est conservé.
    """
    identity = f"{rule_id}\0{file.path}\0{line}\0{file.sha256}"
    return {"rule_id": rule_id, "path": file.path, "line": max(1, line),
            "title": title, "severity": severity, "confidence": confidence,
            "evidence": evidence, "recommendation": recommendation,
            "source_url": source_url, "category": category,
            "fingerprint": hashlib.sha256(identity.encode()).hexdigest()[:24]}


def notice(code, path, message, incomplete=True):
    return {"code": code, "path": path, "message": message, "incomplete": incomplete}
