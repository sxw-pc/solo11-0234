from .store import transaction,record
from . import wave_approval


def propose(db, request_id=None, wave_id=None, applicant=None,
            old_budget=None, new_budget=None, at=None, **extra):
    """Register a risk request and write it as ``draft``.

    The historical positional contract
    ``propose(db, id, wave, applicant, old, new, at)`` keeps returning the exact
    baseline decisions.  Rich keyword content (service, base_version, zone,
    maintenance window, benefited customers, policy) additionally locks the
    original instrument and computes the digest signatures are pinned to.
    """
    # dict-payload calling convention: propose(db, {'op': 'propose', ...})
    if isinstance(request_id, dict):
        payload = dict(request_id)
        payload.setdefault('op', 'propose')
        return wave_approval.run(db, payload)

    bare = not extra
    result = wave_approval.open_request(
        db, request_id=request_id, wave_id=wave_id, applicant=applicant,
        old_budget=old_budget, new_budget=new_budget, at=at, **extra)

    # Preserve the tiny original response contract for bare legacy callers.
    if bare and result.get('decision') in ('draft', 'replay', 'request_conflict'):
        return {'decision': result['decision']}
    return result


def run(db, payload):
    payload = dict(payload)
    payload.setdefault('op', 'propose')
    if 'id' in payload and 'request_id' not in payload:
        payload['request_id'] = payload['id']
    return wave_approval.run(db, payload)
