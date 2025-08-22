import requests, time, sys, json

API = sys.argv[1] if len(sys.argv)>1 else 'http://localhost:8000'

# create small sample in memory
fname = 'sample.txt'
open(fname,'wb').write(b'hello world test sample')

with open(fname,'rb') as f:
    r = requests.post(f'{API}/files', files={'file': (fname,f)})
    r.raise_for_status()
    data = r.json()
    sha256 = data['sha256']
    print('Uploaded', sha256)

for _ in range(30):
    rr = requests.get(f'{API}/files/{sha256}')
    if rr.status_code==200:
        rep = rr.json()
        print('Status:', rep['status'])
        if rep['status']== 'finished':
            print(json.dumps(rep, indent=2))
            break
    time.sleep(1)
else:
    print('Timed out waiting for scan')
