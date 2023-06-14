# k8s-hardening

K8s Hardening guideline in accordence to NSA

Cluster Harening:
Service accounts should not have unneccery permission, Auto mounting SA secret should be restricted
Restricted access to kubernetes api
Keep the cluster version up to date
Permeter security
Use RBAC to control authorisation (can be mapped with a OIDC provider)

System Hardening:
Use seccomp profiling (restricting linux system calls)
Netwrok level security using network policy
Use service mesh like linkerd/istio for ensuring encrypted pod to pod comm
Use of AppArmor
Linux nodes are up to date all paches
Avoid installing unnessary software on the nodes

Secure Microservices:
Use of security context on pod and container level
Enforce restriction using PSP or Pod Security Admission
Optinally use of OPA gatekeeper or Kyvarno to
Make the rootfile system immunatble

System Supplychain:
Have vulnarbility scanning when building image (dont push to repo if not passed the security benchmark we set organisation wide) - preventive
Keep the image lean, refrain from installing unnessary application eg: cur (if needed build image in debug mode like with tag of debug/develop or something)
Use multistage image building to exclude layers which not needed in runtime (we reducing attack surface this way) - https://www.youtube.com/watch?v=hmpUegtHG9s
Run image scanner in the CICD periodically to notify about new vulnerbility
Use imagePolicyWebhook on the admission on control of kubernetes to scan image right before the deployment + set image pull policy to Always

Reference:
Tools -

kubescape
kube-bench
kube-hunter
connaissuer
Trivy
falco
