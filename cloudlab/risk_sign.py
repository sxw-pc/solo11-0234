from .store import transaction,record
from . import wave_approval


def sign(db, signature_id=None, request_id=None, seat=None, at=None, **extra):
    """Accept one external signature onto the immutable signing record.

    The historical positional contract
    ``sign(db, signature_id, request_id, seat, at)`` still returns the same
    ``decision`` values (``missing_request`` / ``signed`` / ``replay`` /
    ``signature_conflict``).  With a registered seat, device code, digest pin,
    delegation or offline receipt time, the result additionally reports
    ``qualified`` and the accountable ultimate ``controller_id`` plus any
    disqualifying reasons.  External signature rows are never rewritten;
    qualification is recomputed from effective-time authority facts.
    """
    if isinstance(signature_id, dict):
        payload = dict(signature_id)
        payload.setdefault('op', 'sign')
        return wave_approval.run(db, payload)

    return wave_approval.accept_signature(
        db, signature_id=signature_id, request_id=request_id, seat=seat, at=at,
        legacy_ok=True, **extra)


def run(db, payload):
    payload = dict(payload)
    payload.setdefault('op', 'sign')
    return wave_approval.run(db, payload)
