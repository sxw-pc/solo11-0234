"""Versioned workload semantics used by the migration gate."""
def effective(manifest, api):
    if api=='old/v1':
        desired=manifest.get('replicas',1)
        minimum=manifest.get('minAvailable',0)
    elif api=='new/v2':
        desired=manifest.get('desiredReplicas',2)
        minimum=manifest.get('availability',{}).get('minimumReady',1)
    else:
        raise ValueError('unsupported API version')
    if not isinstance(desired,int) or not isinstance(minimum,int) or desired<1 or minimum<0 or minimum>desired:
        raise ValueError('invalid availability contract')
    selector=tuple(sorted(manifest.get('selector',{}).items()))
    return {'desired':desired,'minimum_ready':minimum,'selector':selector}
