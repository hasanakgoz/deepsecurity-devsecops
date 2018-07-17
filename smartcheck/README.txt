

# Setup kubectl on mac os x
brew install kubernetes-cli
cp .kube/ from master to local

http://localhost:8001/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/

# Useful commands kubectl
kubectl cluster-info
kubectl get services
kubectl get pods --namespace-kubesystem
kubectl describe nodes
kubectl get nodes
kubectl proxy
kubectl run mydvwa --image=vulnerables/web-dvwa --replicas=1

# Helm Troubleshooting
helm reset --force
helm init

# ##################################
Step-by-step
# ##################################
# Deploy cluster with AWX

ssh 10.200.20.60

# Deploy dashboard
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/master/src/deploy/recommended/kubernetes-dashboard.yaml

Copy .kube and create admintoken
http://localhost:8001/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/


# Install helm
wget https://storage.googleapis.com/kubernetes-helm/helm-v2.9.1-linux-amd64.tar.gz
tar xfvz helm-v2.9.1...
sudo mv linux-amd64/helm /usr/local/bin/helm

helm init

kubectl create serviceaccount --namespace kube-system tiller
you should get: serviceaccount "tiller" created

kubectl create clusterrolebinding tiller-cluster-role --clusterrole=cluster-admin --serviceaccount=kube-system:tiller
you should get: clusterrolebinding "tiller-cluster-role" created

kubectl patch deploy --namespace kube-system tiller-deploy --patch '{"spec":{"template":{"spec":{"serviceAccount":"tiller"}}}}'
You should get: deployment "tiller-deploy" patched

And deploy one more path
kubectl -n kube-system patch deployment tiller-deploy -p '{"spec": {"template": {"spec": {"automountServiceAccountToken": true}}}}'

# Get DSSC
git clone https://github.com/deep-security/smartcheck-helm

cd smartcheck-helm

  # Overrides
create overrides.yaml

service:
  type: ClusterIP
persistence:
  enabled: false

  # Storage class
create gp2-storage-class.yaml

kind: StorageClass
apiVersion: storage.k8s.io/v1
metadata:
  name: gp2
provisioner: kubernetes.io/aws-ebs
parameters:
  type: gp2
reclaimPolicy: Retain
mountOptions:
  - debug

kubectl create -f gp2-storage-class.yaml

# Install DSSC

helm install --namespace smartcheck --set persistence.storageClassName=gp2 --set auth.masterPassword=trendmicro --set activationCode=DK-96KU-2WZD8-MEEVG-RTCJL-3J2Y3-WDTUR --name deepsecurity-smartcheck --values overrides.yaml .

* minimal variant *

helm install --namespace smartcheck --set auth.masterPassword=trendmicro --name deepsecurity-smartcheck --values overrides.yaml .

# Change cni0 on all workernodes to promisc mode
sudo ip link set cni0 promisc on


helm ls --all deepsecurity-smartcheck
NAME                    REVISION  UPDATED                   STATUS    CHART             NAMESPACE
deepsecurity-smartcheck 1         Thu Jul 12 10:46:47 2018  DEPLOYED  smartcheck-1.0.2  smartcheck

export POD_NAME=$(kubectl get pods --namespace smartcheck -l "service=proxy,release=deepsecurity-smartcheck" -o jsonpath="{.items[0].metadata.name}")
   
kubectl get --namespace smartcheck --watch pods $POD_NAME

BAD: export POD_NAME=$(kubectl get pods -l "service=proxy,release=deepsecurity-smartcheck" -o jsonpath="{.items[0].metadata.name}")

export POD_NAME=$(kubectl get pods --namespace smartcheck -l "service=proxy,release=deepsecurity-smartcheck" -o jsonpath="{.items[0].metadata.name}")

kubectl port-forward --namespace smartcheck $POD_NAME 8443:8443

echo Application URL: https://127.0.0.1:8443

echo Username: $(kubectl get --namespace smartcheck secrets -o jsonpath='{.data.userName }' deepsecurity-smartcheck-auth | base64 --decode)
echo Password: $(kubectl get --namespace smartcheck secrets -o jsonpath='{.data.password }' deepsecurity-smartcheck-auth | base64 --decode)




------

kubectl proxy --port=9999 --address='10.200.20.60' --accept-hosts="^*$"
http://10.200.20.60:9999/ui

