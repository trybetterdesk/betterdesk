#!/bin/sh
# Renders neodesk.yaml from the Helm chart with values.yaml. CI runs it and
# fails when the committed neodesk.yaml differs: run it after every change
# to the chart.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
{
    echo "# Rendered from deploy/helm/neodesk with deploy/kubernetes/values.yaml"
    echo "# by deploy/kubernetes/render.sh. Do not edit by hand in the repository."
    helm template neodesk "$here/../helm/neodesk" --namespace neodesk -f "$here/values.yaml"
} > "$here/neodesk.yaml"
