```
cd drp_aa_mvp
pip install -r requirements.txt
sudo apt update
sudo apt install postgresql
createdb authorizedagent -h localhost -p 5432 -U postgres
python manage.py migrate
```

Create superuser named vscode with password `vscode`
```
python manage.py createsuperuser
```

Run/deploy the app:

```
python manage.py collectstatic
cd /workspaces/osiraa/drp_aa_mvp && python3 manage.py runserver 8001
```

See the app in the browser by clicking the prompt VsCode will show you. Go to `/admin` and login with `vscode` `vscode` to see the admin portal.

Add a `Covered Business`:
- Cb ID: 1234
- Discover Endpoint: https://drp.staging.transcen.dental/.well-known/data-rights.json
- API root Endpoint: https://drp.staging.transcen.dental
- Supported Actions: not needed, will be populated from well known endpoint
- Auth bearer token: 1234

Add a `User Identity` so we can submit privacy requests on their behalf:
- email is verified and `dev+drp@transcend.io`

You can view the keys used by the DRP to sign the requests by running `cat drp_aa_mvp/keys.json | jq` after the server starts up.
We will want to use the `verify_key` value to verify that the signatures are valid.