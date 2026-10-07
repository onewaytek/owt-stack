#!/usr/bin/env bash
# Prove that a backup restores, before anyone needs it to.
#
#   templates/openshift/restore-drill.sh <namespace> [online]
#
# In <namespace>, with throwaway names (owt-drill-*), it:
#   1. creates a one-instance CNPG cluster backed up like app.yaml's;
#   2. writes a row, takes a volume-snapshot Backup (offline unless `online` is
#      "true"), then writes a second row;
#   3. bootstraps a second cluster from that Backup, exactly as a restore would;
#   4. passes if the restored database has the first row and not the second;
#   5. deletes everything it made, whatever happened.
#
# It creates and deletes cluster objects, so it needs a namespace admin and is never
# run by CI. Run it after changing how backups are taken (the snapshot class, online
# or offline, the CNPG version), and record the result in the pull request.
set -euo pipefail

NS=${1:?usage: restore-drill.sh <namespace> [online]}
ONLINE=${2:-false}
SNAPSHOT_CLASS=${SNAPSHOT_CLASS:-lvms-vg1}
STORAGE_CLASS=${STORAGE_CLASS:-lvms-vg1}
POSTGRES_MAJOR=${POSTGRES_MAJOR:-18}
SRC=owt-drill-src
DST=owt-drill-restored
BACKUP=owt-drill-backup
oc_ns() { oc -n "$NS" "$@"; }

cleanup() {
  echo "== cleaning up"
  oc_ns delete cluster.postgresql.cnpg.io "$SRC" "$DST" --ignore-not-found --wait=false
  # Its VolumeSnapshot goes with it (snapshotOwnerReference: backup).
  oc_ns delete backup.postgresql.cnpg.io "$BACKUP" --ignore-not-found --wait=false
}
trap cleanup EXIT

cluster() { # name, then extra spec lines
  oc_ns apply -f - <<EOF
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: $1
spec:
  instances: 1
  imageName: ghcr.io/cloudnative-pg/postgresql:$POSTGRES_MAJOR
  storage: {size: 1Gi, storageClass: $STORAGE_CLASS}
  backup:
    volumeSnapshot:
      className: $SNAPSHOT_CLASS
      snapshotOwnerReference: backup
      online: $ONLINE
$2
EOF
}

psql_in() { # cluster, sql
  oc_ns exec "$1-1" -c postgres -- psql -d app -v ON_ERROR_STOP=1 -qAtc "$2"
}

echo "== source cluster ($NS/$SRC, online=$ONLINE)"
cluster "$SRC" "  bootstrap: {initdb: {database: app, owner: app}}"
oc_ns wait --for=condition=Ready "cluster.postgresql.cnpg.io/$SRC" --timeout=10m
psql_in "$SRC" "CREATE TABLE drill (note text); INSERT INTO drill VALUES ('before the backup');"

echo "== backup"
oc_ns apply -f - <<EOF
apiVersion: postgresql.cnpg.io/v1
kind: Backup
metadata:
  name: $BACKUP
spec:
  cluster: {name: $SRC}
  method: volumeSnapshot
  online: $ONLINE
EOF
for _ in $(seq 120); do
  phase=$(oc_ns get "backup.postgresql.cnpg.io/$BACKUP" -o jsonpath='{.status.phase}')
  [ "$phase" = completed ] && break
  [ "$phase" = failed ] && { oc_ns get "backup.postgresql.cnpg.io/$BACKUP" -o yaml; echo "FAIL: the backup failed"; exit 1; }
  sleep 5
done
[ "$phase" = completed ] || { echo "FAIL: the backup did not complete (phase: ${phase:-none})"; exit 1; }
psql_in "$SRC" "INSERT INTO drill VALUES ('after the backup');"

echo "== restore into $DST"
cluster "$DST" "  bootstrap: {recovery: {backup: {name: $BACKUP}, database: app, owner: app}}"
if ! oc_ns wait --for=condition=Ready "cluster.postgresql.cnpg.io/$DST" --timeout=10m; then
  oc_ns get "cluster.postgresql.cnpg.io/$DST" -o jsonpath='{.status.phase}{"\n"}{.status.phaseReason}{"\n"}'
  oc_ns logs -l "cnpg.io/cluster=$DST" --all-containers --tail=40 || true
  echo "FAIL: the restored cluster never became ready"
  exit 1
fi

rows=$(psql_in "$DST" "SELECT note FROM drill ORDER BY note")
echo "restored rows: $rows"
if [ "$rows" = "before the backup" ]; then
  echo "PASS: the backup restores, to the moment it was taken (online=$ONLINE)"
else
  echo "FAIL: expected only 'before the backup'"
  exit 1
fi
