# NeoDesk Helm chart

Runs the NeoDesk server (signal, relay, API and web console in one process)
on Kubernetes, with one replica or several.

```sh
helm install neodesk deploy/helm/neodesk -n neodesk --create-namespace \
  --set publicHost=neodesk.example.com
```

One replica runs as the Docker image does, with SQLite on the volume.

## Several replicas

```sh
helm install neodesk deploy/helm/neodesk -n neodesk --create-namespace \
  --set publicHost=neodesk.example.com \
  --set replicaCount=3 \
  --set postgresql.url='postgres://neodesk:<password>@db:5432/neodesk?sslmode=require' \
  --set valkey.url='rediss://default:<password>@valkey:6379/0' \
  --set persistence.accessMode=ReadWriteMany
```

The chart refuses more than one replica without PostgreSQL, Valkey and a
ReadWriteMany volume, and so does the server: a second instance on SQLite or
without Valkey stops at its start and names what is missing.

- **Valkey or Redis:** Valkey 8 and Redis 7 both work. `rediss://` turns TLS
  on; user and password go in the URL. Every key starts with
  `valkey.keyPrefix` and has a TTL. `valkey.enabled=true` starts a Valkey
  without persistence or password in the release, for tests only.
- **Secrets:** without `secrets.existingSecret` the chart makes a Secret with
  random `API_KEY`, `SESSION_SECRET`, `JWT_SECRET`, `REMOTE_TARGET_VAULT_KEY`
  and `NEODESK_CLUSTER_SECRET`. They stay the same on upgrades, and the
  Secret stays when the release is removed.
- **Key pair:** the first replica makes it on the volume. To bring your own,
  put `id_ed25519` and `id_ed25519.pub` in a Secret and set
  `keyPair.existingSecret`.
- **TLS:** `tls.existingSecret` mounts a `kubernetes.io/tls` Secret (for
  example from cert-manager) and sets `TLS_CERT` and `TLS_KEY`. A renewed
  certificate is read at the next start, so roll the pods after a renewal.
- **Upgrades:** pods are replaced one at a time. The new pod migrates the
  database under a PostgreSQL lock while the old ones keep serving. The
  console's own update and restart buttons are off in a cluster:
  `helm upgrade` with a new `image.tag`, or
  `kubectl rollout restart deployment/neodesk`.
- **Stopping a pod:** it reports not ready, leaves the pod registry, takes
  no new sessions and gives running relay sessions `shutdownGraceSeconds`
  to end.

Sessions keep running when Valkey goes away; new ones fail with a clear
message and the pods report not ready until it is back.

## Plain manifests

`deploy/kubernetes/neodesk.yaml` is this chart rendered for three replicas,
for clusters without Helm. CI checks that it matches the chart.
