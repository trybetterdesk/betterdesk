# NeoDesk on Kubernetes without Helm

`neodesk.yaml` is the Helm chart in `deploy/helm/neodesk` rendered with
`values.yaml`: three replicas, an existing Secret, a ReadWriteMany volume and
an Ingress for the web console. CI renders it again on every change and fails
when the two differ, so it always matches the chart.

Several replicas need PostgreSQL, Valkey 8 or Redis 7, and a volume all pods
can write (NFS, CephFS, EFS, Azure Files). The website's Kubernetes page
explains how the replicas share the work.

## Before you apply it

1. Change `neodesk.example.com` (the address clients connect to, the
   `RELAY_SERVERS` value) and `console.example.com` (the Ingress host) in
   `neodesk.yaml`.
2. Make the namespace and the Secret the pods read:

   ```sh
   kubectl create namespace neodesk
   kubectl -n neodesk create secret generic neodesk-secrets \
     --from-literal=DATABASE_URL='postgres://neodesk:<password>@<host>:5432/neodesk?sslmode=require' \
     --from-literal=VALKEY_URL='rediss://default:<password>@<host>:6379/0' \
     --from-literal=NEODESK_CLUSTER_SECRET="$(openssl rand -hex 32)" \
     --from-literal=API_KEY="$(openssl rand -hex 32)" \
     --from-literal=SESSION_SECRET="$(openssl rand -hex 32)" \
     --from-literal=JWT_SECRET="$(openssl rand -hex 32)" \
     --from-literal=REMOTE_TARGET_VAULT_KEY="$(openssl rand -hex 32)"
   ```

   Keep these values: a new `SESSION_SECRET` signs everyone out, a new
   `REMOTE_TARGET_VAULT_KEY` makes stored target passwords unreadable.
3. `kubectl -n neodesk apply -f neodesk.yaml`

## After a chart change

Run `deploy/kubernetes/render.sh` (it needs `helm`) and commit `neodesk.yaml`.
