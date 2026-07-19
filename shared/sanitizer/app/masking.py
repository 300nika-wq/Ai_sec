"""
Реверсивная маскировка чувствительных данных перед отправкой во внешнюю модель.

Логика: перед отправкой во ВНЕШНЮЮ модель заменяем реальные артефакты
(IP, хосты, домены, e-mail, ФИО, телефоны, токены) на детерминированные
плейсхолдеры. Словарь соответствий (mapping) хранится ТОЛЬКО ЛОКАЛЬНО и
привязан к incident_id / session_id. После получения ответа выполняем
обратную подстановку, чтобы аналитик видел реальные значения в отчёте.

Наружу уходит: TARGET_HOST_1, IP_7, EMAIL_2, PERSON_3 — без реальных данных.
"""
from __future__ import annotations

import re
import hashlib
from dataclasses import dataclass, field
from typing import Dict, Tuple

# Presidio — опциональное усиление PII-детекта (ФИО, телефоны и пр.).
# Если пакет не установлен, работаем на регексах — сервис не падает.
try:
    from presidio_analyzer import AnalyzerEngine
    _ANALYZER = AnalyzerEngine()
    _PRESIDIO = True
except Exception:  # noqa: BLE001
    _ANALYZER = None
    _PRESIDIO = False

# --- Регексы для сетевых артефактов (то, чего Presidio не покрывает точно) ---
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
_IPV6 = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_FQDN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
# Секреты/токены — их вообще НЕ отправляем наружу, заменяем на [REDACTED_SECRET]
_SECRET = re.compile(
    r"(?i)\b(?:eyJ[A-Za-z0-9_-]{10,}"           # JWT
    r"|AKIA[0-9A-Z]{16}"                          # AWS key id
    r"|(?:ghp|gho|ghs)_[A-Za-z0-9]{30,}"          # GitHub token
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"              # Slack token
    r"|-----BEGIN[A-Z ]+PRIVATE KEY-----)"        # private key block
)

# Приватные диапазоны трогаем ВСЕГДА (они и есть цель/инфраструктура),
# но публичные IP тоже маскируем — во внешнюю модель реальные IP не уходят.


@dataclass
class MaskVault:
    """Локальный словарь соответствий. Наружу не сериализуется."""
    session_id: str
    forward: Dict[str, str] = field(default_factory=dict)   # real -> placeholder
    reverse: Dict[str, str] = field(default_factory=dict)   # placeholder -> real
    counters: Dict[str, int] = field(default_factory=dict)

    def placeholder_for(self, real: str, kind: str) -> str:
        if real in self.forward:
            return self.forward[real]
        self.counters[kind] = self.counters.get(kind, 0) + 1
        ph = f"{kind}_{self.counters[kind]}"
        self.forward[real] = ph
        self.reverse[ph] = real
        return ph


def _mask_pattern(text: str, pattern: re.Pattern, kind: str, vault: MaskVault) -> str:
    def repl(m: re.Match) -> str:
        return vault.placeholder_for(m.group(0), kind)
    return pattern.sub(repl, text)


def sanitize(text: str, vault: MaskVault) -> Tuple[str, MaskVault]:
    """Прямая маскировка. Возвращает безопасный текст + обновлённый vault."""
    if not text:
        return text, vault

    # 1. Секреты — вырезаем безвозвратно (наружу и внутрь LLM не нужны).
    text = _SECRET.sub("[REDACTED_SECRET]", text)

    # 2. Сетевые артефакты (порядок важен: сначала email/FQDN, потом IP).
    text = _mask_pattern(text, _EMAIL, "EMAIL", vault)
    text = _mask_pattern(text, _FQDN, "HOST", vault)
    text = _mask_pattern(text, _IPV6, "IP6", vault)
    text = _mask_pattern(text, _IPV4, "IP", vault)
    text = _mask_pattern(text, _MAC, "MAC", vault)

    # 3. PII через Presidio (если доступен): PERSON, PHONE_NUMBER, LOCATION и т.п.
    if _PRESIDIO:
        try:
            results = _ANALYZER.analyze(
                text=text, language="en",
                entities=["PERSON", "PHONE_NUMBER", "CREDIT_CARD", "IBAN_CODE"],
            )
            # Заменяем с конца, чтобы не сбить оффсеты.
            for r in sorted(results, key=lambda x: x.start, reverse=True):
                if r.score < 0.6:
                    continue
                real = text[r.start:r.end]
                ph = vault.placeholder_for(real, r.entity_type)
                text = text[:r.start] + ph + text[r.end:]
        except Exception:  # noqa: BLE001
            pass  # деградация до регексов, сервис не падает

    return text, vault


def desanitize(text: str, vault: MaskVault) -> str:
    """Обратная подстановка реальных значений в ответ модели (для отчёта)."""
    if not text:
        return text
    # Длинные плейсхолдеры первыми, чтобы IP_10 не пострадал от IP_1.
    for ph in sorted(vault.reverse, key=len, reverse=True):
        text = text.replace(ph, vault.reverse[ph])
    return text


def vault_fingerprint(vault: MaskVault) -> str:
    """Хэш словаря для аудита, без раскрытия содержимого."""
    blob = "|".join(f"{k}={v}" for k, v in sorted(vault.forward.items()))
    return hashlib.sha256(blob.encode()).hexdigest()[:16]
