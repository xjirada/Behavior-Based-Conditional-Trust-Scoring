
from enum import Enum, auto
from dataclasses import dataclass

def clamp_score(score: int) -> int:
    return max(0, min(100, score))


class Severity(Enum):
    SAFE = auto()
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()
    UNKNOWN = auto()


class TrustAction(Enum):
    NONE = auto()       
    WARN = auto()        
    CAPTCHA = auto()     
    DELAY = auto()      
    COOLDOWN = auto() 
    TEMP_FREEZE = auto()
    PERM_BAN = auto()    


@dataclass
class TrustDecision:
    old_score: int
    new_score: int
    delta: int
    severity: Severity
    action: TrustAction
    label: str         



SEVERITY_DELTAS = {
    Severity.SAFE: +1,      
    Severity.LOW: -2,
    Severity.MEDIUM: -5,
    Severity.HIGH: -10,
    Severity.CRITICAL: -20,
    Severity.UNKNOWN: -7,    
}


def score_to_profile(score: int) -> str:
    """
    Score 1-100 → label fun versi kamu (hengker, script kiddie, dst).
    Bisa kamu tweak lagi.
    """
    if score <= 10:
        return "hengker (very high risk)"
    if score <= 20:
        return "script kiddie"
    if score <= 30:
        return "nara pemula"
    if score <= 40:
        return "sus"
    if score <= 55:
        return "netral bocil"
    if score <= 65:
        return "lansia / pengguna awam"
    if score <= 80:
        return "boomer / gen Z good user"
    if score <= 95:
        return "reward tier"
    return "hole/admin tier"


def score_to_action(score: int) -> TrustAction:
    """
    Ladder punishment:
    Warn → CAPTCHA → friction/slowdown → cooldown → temp freeze → perm ban
    """
    if score >= 91:
        return TrustAction.NONE              
    if score >= 76:
        return TrustAction.WARN               
    if score >= 61:
        return TrustAction.CAPTCHA              
    if score >= 46:
        return TrustAction.DELAY             
    if score >= 31:
        return TrustAction.COOLDOWN            
    if score >= 16:
        return TrustAction.TEMP_FREEZE        
    return TrustAction.PERM_BAN             


def score_to_label(score: int) -> str:
    action = score_to_action(score)
    if action == TrustAction.NONE:
        return "Trusted — no action."
    if action == TrustAction.WARN:
        return "Low suspicion — passive monitoring and warnings."
    if action == TrustAction.CAPTCHA:
        return "Mild suspicion — CAPTCHA/puzzle for sensitive actions."
    if action == TrustAction.DELAY:
        return "Medium suspicion — progressive delays and extra friction."
    if action == TrustAction.COOLDOWN:
        return "High suspicion — privileged actions disabled for a while."
    if action == TrustAction.TEMP_FREEZE:
        return "Very high suspicion — temporary account freeze."
    if action == TrustAction.PERM_BAN:
        return "CRITICAL — permanent ban recommended."
    return "Unknown."


class TrustEngine:
    """
    Score-based, singular TA (setiap request dilihat independent).
    Nanti bisa kamu upgrade ke contextual TA dengan menyimpan history di sini.
    """

    def apply(self, current_score: int, severity: Severity) -> TrustDecision:
        delta = SEVERITY_DELTAS.get(severity, SEVERITY_DELTAS[Severity.UNKNOWN])
        new_score = clamp_score(current_score + delta)
        action = score_to_action(new_score)
        label = score_to_label(new_score)

        return TrustDecision(
            old_score=current_score,
            new_score=new_score,
            delta=delta,
            severity=severity,
            action=action,
            label=label,
        )

