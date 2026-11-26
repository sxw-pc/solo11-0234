import hashlib
import json
from .store import transaction,record,audit_run

BUILD_FIELDS=('build_inputs_digest','compiler','generated_code_digest','embedded_resources_digest','rebuild_digest')
COMPONENT_FIELDS=('component','source_revision','component_digest','license','origin')
ARCHIVE_FIELDS=('component','source_revision','component_digest','source_digest','license','build_instructions_digest','contents_digest')

def _digest(rows):
    return hashlib.sha256(json.dumps(rows,ensure_ascii=False,sort_keys=True).encode('utf-8')).hexdigest()

def effective_components(db, artifact_id, node_id=None):
    """Components whose bytes actually ship in the binary the node runs.

    Build-time components come from the dependency lock; signed image layers
    loaded after startup override same-named components because the observed
    byte digest wins over the build manifest.
    """
    rows=db.execute('SELECT * FROM artifact_components WHERE artifact_id=? ORDER BY component,component_digest',(artifact_id,)).fetchall()
    # Build-dependency base: only build/repackaged entries belong to the static
    # binary. Runtime-stage rows are candidates that count as shipped only once a
    # node proves it actually loaded them (runtime_loads attestation below).
    merged={r['component']:{'component':r['component'],'source_revision':r['source_revision'],'component_digest':r['component_digest'],
                            'license':r['license'],'origin':r['origin'],'parent_component':r['parent_component'],
                            'stage':r['stage'],'layer_digest':r['layer_digest'],'signature':r['signature']}
            for r in rows if r['stage']!='runtime'}
    if node_id is not None:
        attest=db.execute('SELECT * FROM runtime_attestations WHERE node_id=?',(node_id,)).fetchone()
        if attest:
            loads=db.execute('SELECT * FROM runtime_loads WHERE node_id=? AND generation=? ORDER BY component',
                             (node_id,attest['generation'])).fetchall()
            for r in loads:
                prior=merged.get(r['component'])
                merged[r['component']]={'component':r['component'],'source_revision':r['source_revision'],
                                        'component_digest':r['component_digest'],'license':prior['license'] if prior else None,
                                        'origin':prior['origin'] if prior else None,'parent_component':prior['parent_component'] if prior else None,
                                        'stage':'runtime','layer_digest':r['layer_digest'],'signature':r['signature']}
    return [merged[k] for k in sorted(merged)]

def active_bundle(db, artifact_id, node_id=None):
    sql='SELECT * FROM source_bundles WHERE artifact_id=? AND state=? '
    args=[artifact_id,'active']
    if node_id is not None:
        sql+='AND node_id=? ';args.append(node_id)
    else:
        sql+='AND node_id IS NULL '
    sql+='ORDER BY created_at DESC,id DESC LIMIT 1'
    return db.execute(sql,args).fetchone()

@audit_run('source_custody')
def run(db,x):
    with transaction(db):
        op=x['op']
        if op=='build':
            missing=[k for k in BUILD_FIELDS if not x.get(k)]
            if missing:return {'decision':'blocked','reason':'incomplete_build_material','missing':missing}
            if not x.get('target') or not x.get('architecture') or not x.get('binary_digest'):
                return {'decision':'blocked','reason':'incomplete_build_material'}
            clash=db.execute('SELECT id,target,architecture FROM artifacts WHERE binary_digest=? AND id<>?',(x['binary_digest'],x['id'])).fetchone()
            if clash:return {'decision':'blocked','reason':'binary_digest_conflict','artifact':clash['id']}
            old=db.execute('SELECT * FROM artifacts WHERE id=?',(x['id'],)).fetchone()
            if old:
                if any(old[k]!=x.get(k) for k in BUILD_FIELDS) or old['binary_digest']!=x['binary_digest']:
                    return {'decision':'blocked','reason':'build_identity_conflict'}
                return {'decision':'reused','artifact':x['id']}
            verified=int(bool(x.get('rebuild_verified')))
            db.execute('INSERT INTO artifacts VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                       (x['id'],x['target'],x['architecture'],x['binary_digest'],x['build_inputs_digest'],x['compiler'],
                        x['generated_code_digest'],x['embedded_resources_digest'],x['rebuild_digest'],verified,'registered'))
            record(db,'source_custody',x['id'],'build',1,x)
            return {'decision':'registered','artifact':x['id'],'rebuild_verified':bool(verified)}
        if op=='component':
            artifact=db.execute('SELECT * FROM artifacts WHERE id=?',(x['artifact'],)).fetchone()
            if not artifact:return {'decision':'blocked','reason':'unknown_artifact'}
            missing=[k for k in COMPONENT_FIELDS if not x.get(k)]
            if missing:return {'decision':'blocked','reason':'incomplete_component_provenance','missing':missing}
            stage=x.get('stage','build')
            if stage not in ('build','repackaged','runtime'):
                return {'decision':'blocked','reason':'unknown_component_stage'}
            old=db.execute('SELECT * FROM artifact_components WHERE artifact_id=? AND component=? AND component_digest=?',
                           (x['artifact'],x['component'],x['component_digest'])).fetchone()
            if old:
                if old['source_revision']!=x['source_revision'] or old['license']!=x['license'] or old['origin']!=x['origin']:
                    return {'decision':'blocked','reason':'component_identity_conflict'}
                return {'decision':'reused','component':x['component']}
            db.execute('INSERT INTO artifact_components VALUES(?,?,?,?,?,?,?,?,?,?)',
                       (x['artifact'],x['component'],stage,x['source_revision'],x['component_digest'],
                        x['license'],x['origin'],x.get('parent_component'),x.get('layer_digest'),x.get('signature')))
            record(db,'source_custody',x['artifact'],'component',1,x)
            return {'decision':'recorded','component':x['component'],'stage':stage}
        if op=='archive':
            missing=[k for k in ARCHIVE_FIELDS if not x.get(k)]
            if missing:return {'decision':'blocked','reason':'incomplete_source_archive','missing':missing}
            complete=int(not x.get('incomplete'))
            old=db.execute('SELECT * FROM source_archives WHERE id=?',(x['id'],)).fetchone()
            if old:
                if any(old[k]!=x.get(k) for k in ARCHIVE_FIELDS):
                    return {'decision':'blocked','reason':'archive_identity_conflict'}
                return {'decision':'reused','archive':x['id'],'complete':bool(old['complete'])}
            db.execute('INSERT INTO source_archives VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                       (x['id'],x['component'],x['source_revision'],x['component_digest'],x['source_digest'],
                        x['license'],x['build_instructions_digest'],x['contents_digest'],complete,
                        'complete' if complete else 'incomplete',None,x['at']))
            record(db,'source_custody',x['id'],'archive',1,x)
            return {'decision':'archived','archive':x['id'],'complete':bool(complete)}
        if op=='certify':
            artifact=db.execute('SELECT * FROM artifacts WHERE id=?',(x['artifact'],)).fetchone()
            if not artifact:return {'decision':'blocked','reason':'unknown_artifact'}
            node=None
            if x.get('node'):
                node=db.execute('SELECT * FROM nodes WHERE id=?',(x['node'],)).fetchone()
                if not node:return {'decision':'blocked','reason':'unknown_node'}
                if node['architecture']!=artifact['architecture']:
                    return {'decision':'blocked','reason':'node_architecture_mismatch'}
                if not db.execute('SELECT 1 FROM runtime_attestations WHERE node_id=?',(x['node'],)).fetchone():
                    return {'decision':'blocked','reason':'missing_runtime_attestation'}
            if not artifact['rebuild_verified']:
                return {'decision':'blocked','reason':'static_rebuild_unverified'}
            effective=effective_components(db,x['artifact'],x.get('node'))
            manifest_digest=_digest([{k:c[k] for k in ('component','source_revision','component_digest','license','origin','parent_component','stage','layer_digest','signature')} for c in effective])
            chosen=[];missing=[]
            for c in effective:
                arc=db.execute('SELECT * FROM source_archives WHERE component=? AND component_digest=? AND complete=1 ORDER BY created_at DESC,id DESC LIMIT 1',
                               (c['component'],c['component_digest'])).fetchone()
                if not arc or (c['license'] and arc['license']!=c['license']) or arc['source_revision']!=c['source_revision']:
                    missing.append({'component':c['component'],'component_digest':c['component_digest'],'source_revision':c['source_revision']})
                else:chosen.append(arc)
            complete=not missing
            old=db.execute('SELECT * FROM source_bundles WHERE id=?',(x['id'],)).fetchone()
            if old:
                if old['artifact_id']!=x['artifact'] or old['node_id']!=x.get('node'):
                    return {'decision':'blocked','reason':'bundle_identity_conflict'}
                return {'decision':'reused','bundle':x['id'],'state':old['state']}
            prior=active_bundle(db,x['artifact'],x.get('node'))
            if prior:
                db.execute("UPDATE source_bundles SET state='superseded' WHERE id=?",(prior['id'],))
            bundle_digest=_digest(sorted(a['source_digest'] for a in chosen)) if complete else None
            state='active' if complete else 'incomplete'
            db.execute('INSERT INTO source_bundles VALUES(?,?,?,?,?,?,?,?,?)',
                       (x['id'],x['artifact'],x.get('node'),manifest_digest,bundle_digest,state,
                        None if complete else 'missing_source',prior['id'] if prior else None,x['at']))
            for arc in chosen:
                db.execute('INSERT OR IGNORE INTO bundle_archives VALUES(?,?,?,?)',
                           (x['id'],arc['id'],arc['component'],arc['component_digest']))
            record(db,'source_custody',x['id'],'certify',1,x)
            if not complete:
                return {'decision':'blocked','reason':'source_package_incomplete','bundle':x['id'],'missing':missing}
            return {'decision':'certified','bundle':x['id'],'manifest_digest':manifest_digest,'bundle_digest':bundle_digest,
                    'components':[c['component'] for c in effective]}
        if op=='revoke':
            bundle=db.execute('SELECT * FROM source_bundles WHERE id=?',(x['id'],)).fetchone()
            if not bundle:return {'decision':'blocked','reason':'unknown_bundle'}
            if bundle['state'] in ('revoked','superseded'):
                return {'decision':'reused','bundle':x['id'],'state':bundle['state']}
            db.execute("UPDATE source_bundles SET state='revoked',reason=? WHERE id=?",(x.get('reason','revoked'),x['id']))
            record(db,'source_custody',x['id'],'revoke',2,x)
            return {'decision':'revoked','bundle':x['id'],'retained':True}
        if op=='shipping_manifest':
            bundle=active_bundle(db,x['artifact'],x.get('node'))
            if not bundle:return {'decision':'blocked','reason':'no_active_bundle'}
            arcs=[dict(r) for r in db.execute('SELECT * FROM bundle_archives WHERE bundle_id=? ORDER BY component',(bundle['id'],))]
            record(db,'source_custody',x['artifact'],'shipping_manifest',1,x)
            return {'decision':'manifest','bundle':bundle['id'],'manifest_digest':bundle['manifest_digest'],
                    'bundle_digest':bundle['bundle_digest'],'archives':arcs}
        raise ValueError(op)
