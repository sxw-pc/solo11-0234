import argparse
import json
from pathlib import Path
from .store import connect,report,replay
from . import inventory
from . import wave
from . import migration
from . import media_custody

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('command',choices=["inventory","wave","migration","media_custody","demo","report","replay"])
    parser.add_argument('--db',default='demo.sqlite')
    parser.add_argument('--fixture')
    args=parser.parse_args()
    db=connect(args.db)
    def invoke(module,payload):
        return [module.run(db,step) for step in payload] if isinstance(payload,list) else module.run(db,payload)
    if args.command=='report':
        result=report(db)
    elif args.command=='replay':
        db.close()
        result=replay(args.db,{name:globals()[name] for name in ["inventory","wave","migration","media_custody"]})
    elif args.command=='demo':
        result=[]
        for name,filename in [
            ('inventory','inventory_ok.json'),('inventory','inventory_fail.json'),
            ('migration','migration_ok.json'),('wave','wave_fail.json'),
            ('wave','wave_ok.json'),('migration','migration_fail.json')]:
            file=Path('fixtures')/filename
            payload=json.loads(file.read_text(encoding='utf-8'))
            result.append({'fixture':str(file),'result':invoke(globals()[name],payload)})
    else:
        if not args.fixture: parser.error('--fixture is required')
        payload=json.loads(Path(args.fixture).read_text(encoding='utf-8'))
        result=invoke(globals()[args.command],payload)
    print(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2))
    if args.command=='replay' and not result['verified']: raise SystemExit(2)

if __name__=='__main__': main()
