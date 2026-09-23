# Portal Safe Browsing Monitor

- [Portal Safe Browsing Monitor](#portal-safe-browsing-monitor)
  - [Overview](#overview)
    - [Status](#status)
    - [Alert Logic](#alert-logic)
    - [覆盖范围](#覆盖范围)
    - [API 错误处理](#api-错误处理)
    - [配额与计费](#配额与计费)
    - [Project Structure](#project-structure)
  - [1. Local](#1-local)
    - [1.1 Python](#11-python)
    - [1.2 Web Risk API Key](#12-web-risk-api-key)
    - [1.3 Configure Domains](#13-configure-domains)
    - [1.4 Teams Webhook](#14-teams-webhook)
    - [1.5 Test Teams Webhook](#15-test-teams-webhook)
    - [1.6 Local Run](#16-local-run)
  - [2. Docker](#2-docker)
    - [2.1 Run](#21-run)
    - [2.2 Build and Push](#22-build-and-push)
    - [2.3 Image Version](#23-image-version)
  - [3. Kubernetes](#3-kubernetes)
    - [3.1 Architecture](#31-architecture)
    - [3.2 Namespace](#32-namespace)
    - [3.3 EBS CSI / StorageClass](#33-ebs-csi--storageclass)
    - [3.4 Production PVC](#34-production-pvc)
    - [3.5 Test PVC](#35-test-pvc)
    - [3.6 ConfigMap](#36-configmap)
    - [3.7 Secrets](#37-secrets)
    - [3.8 Test Job](#38-test-job)
    - [3.9 Production CronJob](#39-production-cronjob)
    - [3.10 Manual Trigger CronJob](#310-manual-trigger-cronjob)
    - [3.11 Suspend Production CronJob](#311-suspend-production-cronjob)
    - [3.12 Debug PVC](#312-debug-pvc)
      - [Debug Production PVC](#debug-production-pvc)
      - [Debug Test PVC](#debug-test-pvc)
    - [3.13 Useful Commands](#313-useful-commands)
    - [3.14 Current Deployment Model](#314-current-deployment-model)
  - [4. CI/CD](#4-cicd)
    - [4.1 CI](#41-ci)
    - [4.2 Test CD](#42-test-cd)
    - [4.3 Production CD](#43-production-cd)
  - [5. AWS Lambda（独立部署）](#5-aws-lambda独立部署)
    - [5.0 部署流程（顺序）](#50-部署流程顺序)
    - [5.1 与 Kubernetes 的差异](#51-与-kubernetes-的差异)
    - [5.2 一次性准备（底座）](#52-一次性准备底座)
    - [5.3 部署](#53-部署)
    - [5.4 告警（Teams Webhook）](#54-告警teams-webhook)
    - [5.5 运维](#55-运维)
    - [5.6 注意事项](#56-注意事项)
  - [Migration from Transparency Report](#migration-from-transparency-report)

---

定时通过 Google Web Risk Lookup API 检查配置域名 / URL 的安全状态，并在状态发生变化时通过 Microsoft Teams Workflow Webhook 发送通知。

当前运行方式：

```text
Google Web Risk Lookup API
        ↓
Python (standard library)
        ↓
SAFE / UNSAFE
        ↓
status.json 状态比较
        ↓
状态变化
        ↓
Power Automate Webhook
        ↓
Microsoft Teams
```

Production 运行在 Kubernetes CronJob 中，每 6 小时检查一次（每天 4 轮）。

---

## Overview

### Status

当前支持：

| Status        | Description                          |
| ------------- | ------------------------------------ |
| `SAFE`        | 该 URI 不在任何被查询的威胁列表中    |
| `UNSAFE`      | 该 URI 命中至少一个威胁列表          |
| `CHECK_ERROR` | API 调用异常（超时、429、5xx）       |

Lookup API 的响应只有两种形态。空对象表示未命中：

```json
{}
```

命中时返回威胁类型与缓存过期时间：

```json
{
  "threat": {
    "threatTypes": ["MALWARE"],
    "expireTime": "2026-09-18T15:01:23.045123456Z"
  }
}
```

默认查询的威胁列表，可用 `THREAT_TYPES` 覆盖：

```text
MALWARE
SOCIAL_ENGINEERING
UNWANTED_SOFTWARE
```

命中任意一个都统一记为 `UNSAFE`，具体类型只写入日志，不进入 Webhook 负载。

---

### Alert Logic

首次发现：

```text
FIRST CHECK
    ↓
UNSAFE
    ↓
Teams Alert
    ↓
保存 UNSAFE
```

持续异常：

```text
UNSAFE → UNSAFE
→ No status change
→ 不重复告警
```

恢复：

```text
UNSAFE → SAFE
→ Teams Alert
→ 保存 SAFE
```

持续正常：

```text
SAFE → SAFE
→ 不通知
```

`CHECK_ERROR` 不覆盖之前已经存在的有效 `SAFE / UNSAFE` 状态。

---

### 覆盖范围

Lookup API 是 **URL 级**查询，不是整站判定。

Web Risk 会对传入 URI 展开若干 host 后缀与 path 前缀组合再比对，因此整个域名被列入名单时，查任意路径都会命中。但如果只有某个具体页面被标记，查首页**不会**命中：

```text
https://example.com/            → SAFE
https://example.com/bad/page    → UNSAFE
```

这与之前 Transparency Report 的站点级判定（`Some pages on this site are unsafe`）不同，覆盖面更窄。需要盯具体路径时，在 `domains.txt` 里直接写完整 URL。

---

### API 错误处理

`400 / 401 / 403` 表示 key 无效或 Web Risk API 未启用。重试无意义，且剩余域名会以同样方式失败，因此立即中止整轮并以 `2` 退出：

```text
FATAL: Web Risk rejected the request (HTTP 400).
Check WEBRISK_API_KEY and that the Web Risk API is enabled.
```

其余异常（超时、`429`、`5xx`）按 `MAX_RETRIES` 重试，仍失败则该域名记为 `CHECK_ERROR`，保留上一次有效状态，并在 `FAIL_ON_ERROR=true` 时让进程非 0 退出。

---

### 配额与计费

Lookup API `uris.search` 每月前 100,000 次免费，之后 $0.50 / 1,000 次。

当前 `schedule` 为每 6 小时一轮（每天 4 次），单个域名每月约 120 次：

```text
每天 4 轮 × 145 域名  ≈  17,400 次/月   免费
```

免费额度下这个频率可以撑到约 **833 个域名**，现有清单有充足余量。

供对照，更高频率的成本：

```text
10 分钟一轮 ×  23 域名  ≈  99,360 次/月   免费
10 分钟一轮 × 145 域名  ≈ 626,400 次/月   约 $263/月
60 分钟一轮 × 145 域名  ≈ 104,400 次/月   约 $2/月
```

域名清单较大时，用 `schedule` 降频比其他优化都有效。

注意：一旦调用 Update API 的 `threatLists.computeDiff`，`uris.search` 的单价会跳到 $50 / 1,000 次。本项目只使用纯 Lookup REST 调用，不要引入本地威胁库同步。

---

### Project Structure

```text
portal-monitor/
├── .github/
│   └── workflows/
│       ├── docker-publish.yml
│       ├── cd-test-job.yml
│       ├── cd-cronjob.yml
│       └── cd-lambda.yml
│
├── app/
│   └── monitor.py
│
├── k8s/
│   ├── storageclass.yaml
│   ├── pvc.yaml
│   ├── test-pvc.yaml
│   ├── configmap.yaml
│   ├── test-configmap.yaml
│   ├── test-job.yaml
│   └── cronjob.yaml
│
├── aws/
│   ├── BOOTSTRAP.md
│   ├── bootstrap.yaml
│   ├── lambda_handler.py
│   └── template.yaml
│
├── Dockerfile
├── requirements.txt
├── domains.txt
└── README.md
```

`app/monitor.py` 是共用业务代码。承载可以选 **Kubernetes CronJob**（`k8s/`）或 **AWS Lambda**（`aws/`），二者互不依赖；选 Lambda 时按 `aws/BOOTSTRAP.md` 操作即可。

Runtime 文件不要提交 Git：

```text
status.json
docker-state/
.venv/
.env
```

---

## 1. Local

### 1.1 Python

Monitor 只依赖标准库，`requirements.txt` 为空，不需要 venv，也不需要安装任何包。

确认版本（3.9+）：

```bash
python3 --version
```

macOS 没有 `python` 这个命令，只有 `python3`。本文所有命令都用 `python3`。

---

### 1.2 Web Risk API Key

前置条件：

```text
Google Cloud Project
启用 Web Risk API
创建 API Key
```

启用 API：

```text
Google Cloud Console → APIs & Services → Library → Web Risk API → Enable
```

创建 Key：

```text
APIs & Services → Credentials → Create credentials → API key
```

服务端调用不带 Referer / Origin，所以 Application restrictions 保持 `None`，改用 API restrictions 把 key 限定到 Web Risk：

```text
API restrictions → Restrict key → Web Risk API
```

设置：

```bash
export WEBRISK_API_KEY='YOUR_API_KEY'
```

验证 key 可用（已知的恶意测试 URL，应返回威胁）：

```bash
curl -s "https://webrisk.googleapis.com/v1/uris:search?threatTypes=MALWARE&uri=http%3A%2F%2Ftestsafebrowsing.appspot.com%2Fs%2Fmalware.html&key=$WEBRISK_API_KEY"
```

正常：

```json
{"threat":{"threatTypes":["MALWARE"],"expireTime":"..."}}
```

对照组（干净站点，应返回空对象）：

```bash
curl -s "https://webrisk.googleapis.com/v1/uris:search?threatTypes=MALWARE&uri=https%3A%2F%2Fwww.google.com%2F&key=$WEBRISK_API_KEY"
```

正常：

```json
{}
```

不要输出或提交完整 API Key。

---

### 1.3 Configure Domains

编辑：

```text
domains.txt
```

例如：

```text
portal.boruxa.com
bilibili.com
www.baidu.com
```

裸域名会自动补成 `https://<domain>`。也支持直接写完整 URL 或 host/path：

```text
https://portal.boruxa.com/login
testsafebrowsing.appspot.com/s/malware.html
```

由于 Lookup API 是 URL 级匹配（见 [覆盖范围](#覆盖范围)），需要盯特定页面时必须把完整路径写进来。

一行一个。

支持注释：

```text
# Production
portal.boruxa.com

# Test
testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/
```

---

### 1.4 Teams Webhook

Teams / Power Automate Workflow：

```text
When a Teams webhook request is received
        ↓
Post message in a chat or channel
```

保存 Workflow 后复制 Trigger 的完整 HTTP URL。

设置：

```bash
export ALERT_WEBHOOK_URL='YOUR_WEBHOOK_URL'
```

如果复制出来的 URL 包含 `\`：

```bash
export ALERT_WEBHOOK_URL="${ALERT_WEBHOOK_URL//\\/}"
```

检查 URL 结构：

```bash
python3 - <<'PY'
import os
from urllib.parse import urlparse, parse_qs

u = os.environ["ALERT_WEBHOOK_URL"]
p = urlparse(u)

print("host:", p.hostname)
print("query keys:", list(parse_qs(p.query).keys()))
PY
```

正常应类似：

```text
host: xxxxx.environment.api.powerplatform.com
query keys: ['api-version', 'sp', 'sv', 'sig']
```

不要输出或提交完整 Webhook URL。

---

### 1.5 Test Teams Webhook

```bash
curl -i -X POST "$ALERT_WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "event": "status_changed",
    "domain": "portal-test.example.com",
    "previous": "SAFE",
    "current": "UNSAFE",
    "time": "2026-08-21T09:00:00+08:00"
  }'
```

正常：

```text
HTTP/2 202
```

Teams 应收到：

```text
Safe Browsing Alert

Domain: portal-test.example.com
Previous: SAFE
Current: UNSAFE
```

---

### 1.6 Local Run

如果公司 Zero Trust 导致 SSL verification error，本地测试可临时关闭校验。Webhook 与 Web Risk 是两个独立开关：

```bash
export WEBHOOK_VERIFY_TLS=false
export LOOKUP_VERIFY_TLS=false
```

运行：

```bash
python3 app/monitor.py
```

正常示例：

```text
Checking: portal.boruxa.com
Lookup URI: https://portal.boruxa.com
Attempt 1/3

Previous: SAFE
Current : SAFE

✅ SAFE: portal.boruxa.com
No status change.
```

首次发现 UNSAFE：

```text
Checking: testsafebrowsing.appspot.com/s/malware.html
Lookup URI: https://testsafebrowsing.appspot.com/s/malware.html
Attempt 1/3
Threat types: MALWARE

Previous: (first check)
Current : UNSAFE

🚨 UNSAFE: testsafebrowsing.appspot.com/s/malware.html
🚨 FIRST CHECK AND UNSAFE

Webhook HTTP: 202
```

Local 状态保存在：

```text
status.json
```

---

## 2. Docker

### 2.1 Run

镜像里已经 `COPY` 了一份 `domains.txt`，状态默认写在容器内的 `/data/status.json`。容器删掉状态就没了，所以要把 `/data` 挂到宿主机，否则每次都是「首次检查」，已经是 UNSAFE 的域名会重复告警。

拉镜像：

```bash
docker pull lifebytehub/portal-monitor:v1.0.0
```

运行：

```bash
mkdir -p docker-state

docker run --rm \
  -v "$PWD/docker-state:/data" \
  -e WEBRISK_API_KEY="$WEBRISK_API_KEY" \
  -e ALERT_WEBHOOK_URL="$ALERT_WEBHOOK_URL" \
  lifebytehub/portal-monitor:v1.0.0
```

状态落在：

```text
docker-state/status.json
```

用本地的域名清单覆盖镜像里那份：

```bash
docker run --rm \
  -v "$PWD/docker-state:/data" \
  -v "$PWD/domains.txt:/app/domains.txt:ro" \
  -e WEBRISK_API_KEY="$WEBRISK_API_KEY" \
  -e ALERT_WEBHOOK_URL="$ALERT_WEBHOOK_URL" \
  lifebytehub/portal-monitor:v1.0.0
```

只检查、不发通知（不传 `ALERT_WEBHOOK_URL` 即可）：

```bash
docker run --rm \
  -v "$PWD/docker-state:/data" \
  -e WEBRISK_API_KEY="$WEBRISK_API_KEY" \
  lifebytehub/portal-monitor:v1.0.0
```

公司 Zero Trust 做 TLS 检查导致证书校验失败时，可临时关掉。两个开关分别对应 Web Risk 和 Webhook，不要当生产默认：

```bash
docker run --rm \
  -v "$PWD/docker-state:/data" \
  -e WEBRISK_API_KEY="$WEBRISK_API_KEY" \
  -e ALERT_WEBHOOK_URL="$ALERT_WEBHOOK_URL" \
  -e LOOKUP_VERIFY_TLS=false \
  -e WEBHOOK_VERIFY_TLS=false \
  lifebytehub/portal-monitor:v1.0.0
```

查看状态：

```bash
cat docker-state/status.json
```

`docker-state/` 不要提交 Git。

---

### 2.2 Build and Push

Build：

```bash
docker buildx build \
  --platform linux/amd64 \
  -t lifebytehub/portal-monitor:test \
  .
```

Push：

```bash
docker login
```

然后：

```bash
docker push lifebytehub/portal-monitor:test
```

正式 CI 使用：

```text
lifebytehub/portal-monitor
```

---

### 2.3 Image Version

开发提交使用 Git SHA：

```text
lifebytehub/portal-monitor:sha-96b8ec3
```

正式 Release：

```text
lifebytehub/portal-monitor:v1.0.0
lifebytehub/portal-monitor:v1.0.1
```

推荐流程：

```text
main push
   ↓
CI
   ↓
sha-xxxxxxx
   ↓
Test Job
   ↓
验证
   ↓
Git Tag v1.x.x
   ↓
Production CronJob
```

---

## 3. Kubernetes

### 3.1 Architecture

Namespace：

```text
portal-monitor
```

结构：

```text
portal-monitor
│
├── ConfigMap
│   └── portal-monitor-config
│       └── domains.txt
│
├── Secret
│   ├── portal-monitor-webrisk
│   │   └── Web Risk API Key
│   └── portal-monitor-alert
│       └── Teams Webhook
│
├── Test PVC
│   └── portal-monitor-state-test
│
├── Production PVC
│   └── portal-monitor-state
│
├── Test Job
│   └── portal-monitor-test
│
└── Production CronJob
    └── portal-monitor
```

Test 与 Production 使用不同 PVC，避免测试修改 Production 状态。

---

### 3.2 Namespace

首次创建：

```bash
kubectl create namespace portal-monitor
```

设置当前 context：

```bash
kubectl config set-context \
  --current \
  --namespace=portal-monitor
```

确认：

```bash
kubectl config view --minify \
  -o jsonpath='{..namespace}'; echo
```

应返回：

```text
portal-monitor
```

---

### 3.3 EBS CSI / StorageClass

确认 EBS CSI：

```bash
kubectl get pods -n kube-system | grep ebs
```

应看到：

```text
ebs-csi-controller
ebs-csi-node
```

确认 StorageClass：

```bash
kubectl get storageclass
```

Production 使用：

```text
gp3
```

Provisioner：

```text
ebs.csi.aws.com
```

---

### 3.4 Production PVC

```bash
kubectl apply -f k8s/pvc.yaml
```

PVC：

```text
portal-monitor-state
```

挂载：

```text
/data
```

状态文件：

```text
/data/status.json
```

---

### 3.5 Test PVC

```bash
kubectl apply -f k8s/test-pvc.yaml
```

PVC：

```text
portal-monitor-state-test
```

Test Job 使用该 PVC，不修改 Production `status.json`。

查看：

```bash
kubectl get pvc
```

可能先显示：

```text
Pending
```

如果 StorageClass 是：

```text
WaitForFirstConsumer
```

属于正常现象。

Pod 创建后 EBS 会动态创建并变成：

```text
Bound
```

---

### 3.6 ConfigMap

域名配置：

```bash
kubectl apply -f k8s/configmap.yaml
```

查看：

```bash
kubectl get configmap portal-monitor-config
```

修改域名只需要更新：

```text
k8s/configmap.yaml
```

然后：

```bash
kubectl apply -f k8s/configmap.yaml
```

不需要重新 Build Docker Image。

---

### 3.7 Secrets

需要两个 Secret。

Web Risk API Key：

```bash
export WEBRISK_API_KEY='YOUR_API_KEY'

kubectl create secret generic portal-monitor-webrisk \
  --from-literal=api-key="$WEBRISK_API_KEY"
```

Teams Webhook：

```bash
export ALERT_WEBHOOK_URL='YOUR_WEBHOOK_URL'

kubectl create secret generic portal-monitor-alert \
  --from-literal=webhook-url="$ALERT_WEBHOOK_URL"
```

确认：

```bash
kubectl get secret portal-monitor-webrisk portal-monitor-alert
```

轮换 API Key：

```bash
kubectl create secret generic portal-monitor-webrisk \
  --from-literal=api-key="$WEBRISK_API_KEY" \
  --dry-run=client -o yaml | kubectl apply -f -
```

下一轮 CronJob 自动生效，不需要重新部署。

不要把 API Key 或 Webhook URL 提交到 Git。

---

### 3.8 Test Job

Test 环境使用：

```text
Image: sha-xxxxxxx
PVC: portal-monitor-state-test
Workload: Job
```

查看：

```bash
kubectl get jobs
```

日志：

```bash
kubectl logs job/portal-monitor-test -f
```

Test Job 完成后：

```text
STATUS: Complete
```

不会持续占用 CPU / Memory。

镜像由 CD 写入 `IMAGE_PLACEHOLDER`。不要直接 `kubectl apply -f k8s/test-job.yaml`。

测试 Job 设置了 `FAIL_ON_ERROR=true`：`CHECK_ERROR` 或 Webhook 失败时进程非 0 退出，Job 被标记为 Failed。API Key 无效会直接以 `2` 退出。

CD 是一次性部署，只等待 Pod 启动（3 分钟），不等待 Job 跑完，因此**不会**因为 Job 失败而失败。Job 的最终结果需要自行查看：

```bash
kubectl get job portal-monitor-test -n portal-monitor
kubectl logs -f -n portal-monitor job/portal-monitor-test
```

`kubectl get job` 的 `DURATION` 列即本次跑完耗时。改用 Lookup API 后一轮只有 HTTP 调用，`activeDeadlineSeconds` 已从 28800 降到 600。

---

### 3.9 Production CronJob

Production：

```text
Image: v1.x.x
PVC: portal-monitor-state
Schedule: every 6 hours (4 runs per day)
Time zone: Asia/Shanghai
```

查看：

```bash
kubectl get cronjob portal-monitor
```

当前 Schedule：

```yaml
schedule: "0 */6 * * *"
timeZone: Asia/Shanghai
```

即北京时间：

```text
00:00   06:00   12:00   18:00
```

CronJob 默认按 UTC 执行，`spec.timeZone` 自 Kubernetes 1.27 起为正式特性。确认生效：

```bash
kubectl get cronjob portal-monitor \
  -o jsonpath='{.spec.timeZone}'; echo
```

应返回：

```text
Asia/Shanghai
```

如果返回为空，说明字段被 API Server 丢弃（集群低于 1.27），此时实际仍按 UTC 跑，需要改回 `0 16,22,4,10 * * *` 之类的 UTC 表达式。

检测延迟的上限即一个周期，也就是最坏情况下域名被标记 6 小时后才告警。

镜像由 `cd-cronjob.yml` 把 `IMAGE_PLACEHOLDER` 换成 `v1.x.x` 后 apply。不要直接 `kubectl apply -f k8s/cronjob.yaml`。

CronJob 使用：

```yaml
concurrencyPolicy: Forbid
```

避免 CronJob 自身产生多个并发 Job。

---

### 3.10 Manual Trigger CronJob

生产 PVC 是 RWO。手工 Job 和到点的 CronJob 会抢同一块盘。

先暂停 CronJob，再手工创建：

```bash
kubectl patch cronjob portal-monitor \
  --type merge \
  -p '{"spec":{"suspend":true}}'

kubectl create job \
  --from=cronjob/portal-monitor \
  portal-monitor-manual-test
```

查看：

```bash
kubectl logs \
  job/portal-monitor-manual-test \
  -f
```

完成后删除：

```bash
kubectl delete job portal-monitor-manual-test
```

注意：

`concurrencyPolicy: Forbid` 只限制 CronJob 自动创建的 Job，不限制手工创建的 Job。手工跑完后记得恢复 `suspend: false`。

---

### 3.11 Suspend Production CronJob

测试期间如果不希望 Production 自动运行：

```bash
kubectl patch cronjob portal-monitor \
  -p '{"spec":{"suspend":true}}'
```

恢复：

```bash
kubectl patch cronjob portal-monitor \
  -p '{"spec":{"suspend":false}}'
```

确认：

```bash
kubectl get cronjob portal-monitor
```

---

### 3.12 Debug PVC

Job / CronJob Pod 完成后：

```text
STATUS = Succeeded / Completed
```

不能再：

```bash
kubectl exec
```

例如会出现：

```text
cannot exec into a container in a completed pod
```

此时可以创建临时 Debug Pod 挂载 PVC。

---

#### Debug Production PVC

```bash
kubectl run pvc-debug \
  -n portal-monitor \
  --image=busybox \
  --restart=Never \
  --overrides='
{
  "spec": {
    "containers": [{
      "name": "pvc-debug",
      "image": "busybox",
      "command": ["sh", "-c", "sleep 3600"],
      "volumeMounts": [{
        "name": "state",
        "mountPath": "/data"
      }]
    }],
    "volumes": [{
      "name": "state",
      "persistentVolumeClaim": {
        "claimName": "portal-monitor-state"
      }
    }]
  }
}'
```

确认：

```bash
kubectl get pod pvc-debug
```

进入：

```bash
kubectl exec -it pvc-debug -- sh
```

查看：

```sh
ls -lah /data
```

查看状态：

```sh
cat /data/status.json
```

退出：

```sh
exit
```

删除 Debug Pod：

```bash
kubectl delete pod pvc-debug
```

---

#### Debug Test PVC

如果需要查看 Test 状态，只需要把：

```text
portal-monitor-state
```

换成：

```text
portal-monitor-state-test
```

即：

```json
"persistentVolumeClaim": {
  "claimName": "portal-monitor-state-test"
}
```

然后：

```bash
kubectl exec -it pvc-debug -- sh
```

查看：

```sh
cat /data/status.json
```

---

### 3.13 Useful Commands

查看 Pod：

```bash
kubectl get pods
```

只看 Running：

```bash
kubectl get pods \
  --field-selector=status.phase=Running
```

查看 Job：

```bash
kubectl get jobs
```

查看 CronJob：

```bash
kubectl get cronjob
```

查看 PVC：

```bash
kubectl get pvc
```

查看 PV：

```bash
kubectl get pv
```

查看 Production Image：

```bash
kubectl get cronjob portal-monitor \
  -o jsonpath='{.spec.jobTemplate.spec.template.spec.containers[0].image}'; echo
```

查看 Test Job Image：

```bash
kubectl get job portal-monitor-test \
  -o jsonpath='{.spec.template.spec.containers[0].image}'; echo
```

查看日志：

```bash
kubectl logs job/portal-monitor-test
```

查看 CronJob 最近产生的 Jobs：

```bash
kubectl get jobs \
  --sort-by=.metadata.creationTimestamp
```

---

### 3.14 Current Deployment Model

Kubernetes 路线的端到端流程（与第 4 节 CI/CD、第 3.8–3.9 节 manifest 对应）：

```text
Developer
   │
   └── git push main
          ↓
         CI
          ↓
Docker Hub :sha-xxxxxxx
          ↓
     Automatic Test CD
          ↓
       Test Job
          ↓
 Test PVC / status.json
          ↓
       Validation
          ↓
      Git Tag v1.x.x
          ↓
 Docker Hub :v1.x.x
          ↓
  Manual Test Job (same tag)
          ↓
    Production CD
          ↓
 Production CronJob
          ↓
  Every 6 Hours
          ↓
 Google Web Risk Lookup API
          ↓
      Status Change
          ↓
      Teams Alert
```

---

## 4. CI/CD

### 4.1 CI

GitHub Actions：

```text
main push
   ↓
Build Docker
   ↓
Push Docker Hub
   ↓
sha-xxxxxxx
```

例如：

```text
lifebytehub/portal-monitor:sha-c0691a8
```

Git Tag：

```bash
git tag v1.0.1
git push origin v1.0.1
```

生成：

```text
lifebytehub/portal-monitor:v1.0.1
```

---

### 4.2 Test CD

工作流：`.github/workflows/cd-test-job.yml`

`main` 上 CI 成功后自动跑 Test Job，镜像是 `sha-xxxxxxx`：

```text
CI success
    ↓
CD Test Job
    ↓
Deploy sha-xxxxxxx
    ↓
portal-monitor-test
    ↓
portal-monitor-state-test
    ↓
Completed
```

打 `v*` tag 会再构建一份生产镜像，**不会**自动跑 Test Job。上生产前用同一个 tag 手动跑一次：

Actions → **CD - Test** → Run workflow → `image_tag` 填 `v1.0.1`

---

### 4.3 Production CD

工作流：`.github/workflows/cd-cronjob.yml`（手动，输入 `v1.x.x`）

```text
SHA Test Passed
    ↓
git tag v1.x.x  (打在已测过的那个 commit 上)
    ↓
Docker Hub :v1.x.x
    ↓
CD Test Job (手动，同一 tag)
    ↓
CD Production
    ↓
Update CronJob
```

查看 Production 当前 Image：

```bash
kubectl get cronjob portal-monitor \
  -o jsonpath='{.spec.jobTemplate.spec.template.spec.containers[0].image}'; echo
```

例如：

```text
lifebytehub/portal-monitor:v1.0.0
```

---

## 5. AWS Lambda（独立部署）

在 **LB-INFRA-PROD-972910065688** / **ap-east-1** 上运行的无服务器部署方式：EventBridge 定时触发 Lambda，状态与域名清单放在 S3，CD 走 GitHub Actions OIDC。与 Kubernetes 路线**无运行时耦合**——不必建集群、不必推 Docker 镜像。细节见 **[aws/BOOTSTRAP.md](aws/BOOTSTRAP.md)**。

### 5.0 部署流程（顺序）

Lambda 路线从空底座到定时监控的顺序（与 §5.2–§5.3、`cd-lambda.yml` 对应）：

```text
Infra-admin（账号 972910065688，一次）
   │
   └── cloudformation deploy  aws/bootstrap.yaml
          ↓
   S3 Bucket + IAM Role portal-monitor-github-deploy
          ↓
   aws s3 cp domains.txt → s3://…/portal-monitor/domains.txt
          ↓
   GitHub Secrets
   （AWS_DEPLOY_ROLE_ARN / AWS_STATE_BUCKET / WEBRISK_API_KEY / ALERT_WEBHOOK_URL 按需）
          ↓
Developer
   │
   └── Actions → CD - Deploy Lambda
       （Use workflow from: main · ref · enable_webhook）
          ↓
   GitHub OIDC 假扮 Deploy Role
          ↓
   打包 monitor.py + lambda_handler.py → zip → S3
          ↓
   cloudformation deploy  aws/template.yaml
          ↓
   Lambda + EventBridge Scheduler（默认定时 DISABLED）
          ↓
   Smoke invoke（需有效 WEBRISK_API_KEY 才完整成功）
          ↓
   （上线）ScheduleState=ENABLED
          ↓
   每天 4 次（Asia/Shanghai）触发 Lambda
          ↓
   S3 读 domains.txt + status.json
          ↓
   monitor.main() → 回写 status.json
          ↓
   Google Web Risk Lookup API
          ↓
   状态变化 → Teams（enable_webhook=true 且已配 Webhook 时）
```

### 5.1 与 Kubernetes 的差异

承载方式不同的地方只有三处：

| | Kubernetes CronJob | AWS Lambda |
| --- | --- | --- |
| 打包 | Docker 镜像（Docker Hub） | zip 部署包，约 8 KB |
| 状态 | PVC `/data/status.json` | S3 `portal-monitor/status.json` |
| 域名清单 | ConfigMap | S3 `portal-monitor/domains.txt` |
| 定时 | CronJob `spec.timeZone` | EventBridge Scheduler `ScheduleExpressionTimezone` |
| 部署 | `cd-cronjob.yml` | `cd-lambda.yml` |

`monitor.py` 只认环境变量和文件路径，对自己跑在哪里无感知。Lambda 侧的差异全部由 `aws/lambda_handler.py` 吸收：

```text
S3 → /tmp → monitor.main() → /tmp → S3
```

Lambda 没有持久化磁盘，`/tmp` 跨调用不保证保留。handler 每轮从 S3 拉状态、跑完传回，并在 S3 上没有状态时清掉 `/tmp` 里可能残留的旧文件（warm container 复用会留下上一次的 `status.json`）。

Lambda 路线不需要 Docker Hub。`monitor.py` 无第三方依赖，`boto3` 由运行时自带，所以部署包只有两个文件。

---

### 5.2 一次性准备（底座）

目标账号是 `LB-INFRA-PROD-972910065688`，Region `ap-east-1`。不要手搓 IAM / Bucket，用 bootstrap Stack 一次建好底座，再跑日常 CD：

完整步骤见 **[aws/BOOTSTRAP.md](aws/BOOTSTRAP.md)**。摘要：

```text
1. aws cloudformation deploy  aws/bootstrap.yaml
      → S3 Bucket
      → IAM Role portal-monitor-github-deploy
      （GitHub OIDC Provider 复用账号现有的，不重建）

2. 上传 domains.txt 到 Bucket
3. 填 GitHub Secrets（Role ARN / Bucket / Web Risk Key；Webhook 按需）
4. Actions → CD - Deploy Lambda
```

```bash
export AWS_PROFILE=LB-INFRA-PROD-972910065688
export AWS_REGION=ap-east-1
export STATE_BUCKET="portal-monitor-infra-972910065688"

aws cloudformation deploy \
  --region "$AWS_REGION" \
  --stack-name portal-monitor-bootstrap \
  --template-file aws/bootstrap.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    StateBucketName="$STATE_BUCKET" \
    GitHubOrg=jevinwang-lb \
    GitHubRepo=portal-monitor-local
```

两个参数都用模板默认值：`CreateOidcProvider=false` 复用账号现有的 Terraform 托管 Provider，`GitHubRefFilter=ref:refs/heads/main` 限定只有从 `main` dispatch 的 run 能假扮 Deploy Role。部署哪个分支的代码由 workflow 的 `ref` 输入控制，跟这个过滤器无关。

改域名只重新 `aws s3 cp domains.txt s3://$STATE_BUCKET/portal-monitor/domains.txt`，不用重新部署，与 ConfigMap 的用法对应。

---

### 5.3 部署

Actions → **CD - Deploy Lambda** → Run workflow：

```text
Use workflow from   main          # OIDC 须匹配 bootstrap 的 GitHubRefFilter
ref                 main          # 打进 zip 的代码版本
enable_webhook      true / false  # 见 5.4
```

Workflow 依次做：打包 zip → 上传 S3 → `aws cloudformation deploy` → 等待函数更新 → 执行一次冒烟调用并打印日志。CD 最后一步在缺少有效 `WEBRISK_API_KEY` 时会失败，属预期；infra 与 key 都就绪后应变绿。

Stack 由 `aws/template.yaml` 定义，包含 Lambda、执行角色、日志组、EventBridge Scheduler 及其调用角色。调度默认：

```yaml
ScheduleExpression: cron(0 0,6,12,18 * * ? *)
ScheduleExpressionTimezone: Asia/Shanghai
```

即北京时间 00:00 / 06:00 / 12:00 / 18:00。新建 Stack 时 **Schedule 默认 DISABLED**，Web Risk 与冒烟 invoke 都通过后再在 `BOOTSTRAP.md` 里按说明设为 ENABLED。

---

### 5.4 告警（Teams Webhook）

- **`enable_webhook=false`**（默认）：Lambda 照常查域名、写 `status.json`，不调用 Teams。可不配置 `ALERT_WEBHOOK_URL`。
- **`enable_webhook=true`**：须在 GitHub 配置 Secret **`ALERT_WEBHOOK_URL`**，CD 会把它写入 Lambda 环境变量。

`monitor.py` 在未配置 webhook 时只打日志：

```text
INFO: ALERT_WEBHOOK_URL not configured
```

---

### 5.5 运维

看日志：

```bash
aws logs tail /aws/lambda/portal-monitor --follow
```

手动跑一次：

```bash
aws lambda invoke \
  --function-name portal-monitor \
  --payload '{}' \
  --cli-binary-format raw-in-base64-out \
  response.json && cat response.json
```

查看状态：

```bash
aws s3 cp "s3://$STATE_BUCKET/portal-monitor/status.json" -
```

删除整套：

```bash
aws cloudformation delete-stack --stack-name portal-monitor
```

Bucket 不在 Stack 内，不会被一起删掉。

---

### 5.6 注意事项

1. **账号与 Region**：仅 **`972910065688`** / **`ap-east-1`**。bootstrap 不要设 `CreateOidcProvider=true`（会动到全账号共用的 GitHub OIDC Provider）。
2. **GitHub OIDC `sub`**：2026-07 后新建的仓库带 owner/repo ID，bootstrap 信任策略需含 `repo:org@*/repo@*` 模式（见当前 `aws/bootstrap.yaml`）。CD 必须从 **`main`** dispatch（与 `GitHubRefFilter` 一致）。
3. **Secrets**：GitHub **不能存空 secret**；`WEBRISK_API_KEY` 要么不建（Lambda 里为空），要么填非空（真 key 或占位）。占位 key 会在 invoke 得到 Google `API_KEY_INVALID`。
4. **Schedule**：默认定时 **关闭**；key 与 invoke 验证通过后再 `ScheduleState=ENABLED`（见 `aws/BOOTSTRAP.md`）。
5. **首次运行与 S3**：执行角色需对 `portal-monitor/` 前缀有 **`s3:ListBucket`**，否则缺少 `status.json` 时 HeadObject 会 403（已在 `aws/template.yaml` 修复）。
6. **域名与配额**：Web Risk 按 URL 计费；默认定时每天 4 次，注意域名数量与 [免费额度](https://cloud.google.com/web-risk/pricing)（约 10 万次/月）。
7. **与 Kubernetes 路线**：仓库虽同时含 `k8s/` 与 `aws/`，**生产上只应跑一种**定时监控实例，并只开一路 Teams 告警，避免同一域名变更通知两次。若只用 Lambda，无需操作 EKS / CronJob。
8. **拆除**：删 Stack `portal-monitor` 不会删 bootstrap 桶（`DeletionPolicy: Retain`）；版本控制桶需按 `BOOTSTRAP.md` §7 按版本清空后再删桶。
9. **CD 触发**：`cd-lambda.yml` 为 **workflow_dispatch**，不手动 Run 不会部署；临时停用可用 GitHub **Disable workflow**，勿把 YAML 注释掉留在仓库。

---

## Migration from Transparency Report

早期 POC 抓取公开的 Google Safe Browsing Transparency Report 页面（Playwright + Chromium）。Transparency Report 不是公开 API，Google 会按出口 IP 和浏览器指纹限流，机房 / 共享 NAT 出口长期会被判定为自动化流量并跳转 `/sorry/index`，监控因此需要一个 `BLOCKED` 状态来避免静默失明。降并发、加抖动间隔、伪装 UA 只能降低概率，无法根治。

改用 Web Risk Lookup API 后：

| 项目             | Transparency Report                            | Web Risk Lookup API           |
| ---------------- | ---------------------------------------------- | ----------------------------- |
| 判定粒度         | 站点级                                         | URL 级                        |
| 反爬拦截         | 长期存在，需 `BLOCKED` 状态                    | 无                            |
| 状态枚举         | SAFE / UNSAFE / UNKNOWN / NO_DATA / BLOCKED    | SAFE / UNSAFE                 |
| 运行时依赖       | Playwright + Chromium                          | 标准库                        |
| 镜像体积         | 约 1.8 GB                                      | 约 160 MB                     |
| 单域名耗时       | 数秒至数十秒                                   | 一次 HTTP 调用                |
| 凭证             | 无                                             | GCP Project + API Key         |
| 成本             | 免费                                           | 每月 10 万次内免费            |

保持不变的部分：`domains.txt` 格式、`status.json` 状态比较、Teams Webhook 负载结构、`FAIL_ON_ERROR` 语义、K8s 编排与 CI/CD 流程。

`BLOCKED` 从未写入 `status.json`（命中时保留 previous），因此存量状态文件无需清理，Power Automate 侧也不用改 schema。

需要回退时不必改代码，把 CronJob 的 image 指回 Transparency Report 版本的 tag 即可：

```bash
kubectl get cronjob portal-monitor \
  -o jsonpath='{.spec.jobTemplate.spec.template.spec.containers[0].image}'; echo
```
