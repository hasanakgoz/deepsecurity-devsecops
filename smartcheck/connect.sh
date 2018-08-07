#!/bin/sh
export POD_NAME=$(kubectl get pods --namespace smartcheck -l "service=proxy,release=deepsecurity-smartcheck" -o jsonpath="{.items[0].metadata.name}")
echo Password: $(kubectl get --namespace smartcheck secrets -o jsonpath='{.data.password }' deepsecurity-smartcheck-auth | base64 --decode)
kubectl proxy &
kubectl port-forward --namespace smartcheck $POD_NAME 8443:8443 &