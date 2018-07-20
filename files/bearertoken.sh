#!/bin/sh

# get p12 with client-certificate-data and client-key-data
grep 'client-certificate-data' /home/ubuntu/.kube/config | head -n 1 | awk '{print $2}' | base64 -d > /home/ubuntu/kubecfg.crt

grep 'client-key-data' /home/ubuntu/.kube/config | head -n 1 | awk '{print $2}' | base64 -d > /home/ubuntu/kubecfg.key

openssl pkcs12 -export -clcerts -inkey /home/ubuntu/kubecfg.key -in /home/ubuntu/kubecfg.crt -out /home/ubuntu/kubecfg.p12 -name "kubernetes-client" -passout pass:
# import the kubecfg.p12 certificate, reopen your browser

# create service acc
cat <<EOF | kubectl create -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin-user
  namespace: kube-system
EOF

# create ClusterRoleBinding
cat <<EOF | kubectl create -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-user
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: admin-user
  namespace: kube-system
EOF

# get the bearer token
kubectl -n kube-system describe secret $(kubectl -n kube-system get secret | grep admin-user | awk '{print $1}') > /home/ubuntu/admintoken.txt
