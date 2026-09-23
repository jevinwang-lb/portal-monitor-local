# Portal Monitor — Infra 账号 Bootstrap

目标账号固定为 **`LB-INFRA-PROD-972910065688`**，Region `ap-east-1`。不涉及其他账号。

从零到能跑 `CD - Deploy Lambda` 的操作清单。业务代码（`app/monitor.py`）不变，这里只建 **一次性底座**：

| 资源 | 谁创建 | 用途 |
| --- | --- | --- |
| S3 Bucket | `aws/bootstrap.yaml` | `domains.txt` / `status.json` / 部署 zip |
| GitHub OIDC Provider | 复用账号现有（Terraform 管理，不重建） | Actions 无 AK/SK 假扮 AWS |
| IAM Role `portal-monitor-github-deploy` | `aws/bootstrap.yaml` | CD workflow 假扮的角色 |
| Lambda + Scheduler | `aws/template.yaml`（现有 `cd-lambda.yml`） | 日常部署 |

```text
你（972910065688 的 Infra-admin）
        │
        │  1. aws cloudformation deploy  bootstrap.yaml
        ▼
   S3 + Deploy Role
        │
        │  2. 填 GitHub Secrets + 上传 domains.txt
        ▼
   Actions → CD - Deploy Lambda
        │
        │  3. cd-lambda.yml → template.yaml
        ▼
   Lambda + EventBridge Scheduler
```

Region 固定 `ap-east-1`（香港）：该账号的 EKS 集群（含 `lb-infra-nonprod-web-eks-hk-test-01`）都在这里，Lambda 与现有 CronJob 同 Region。`cd-lambda.yml` 的 `env.AWS_REGION` 已是此值。

---

## 0. 前置

### 0.1 AWS

- 账号 `972910065688`，SSO profile `LB-INFRA-PROD-972910065688`，角色 `Infra-admin`
- 本机已 `aws login`，当前身份落在该账号

确认：

```bash
export AWS_PROFILE=LB-INFRA-PROD-972910065688
aws sts get-caller-identity
```

`Account` 应是 `972910065688`。该 profile 默认 Region 是 `ap-southeast-2`，所以下面每步都显式带 `--region`，或先设：

```bash
export AWS_REGION=ap-east-1
```

### 0.2 GCP（Web Risk）

Lambda 调用的是 Google Web Risk，不是 AWS 服务：

1. GCP Project 启用 **Web Risk API**（`webrisk.googleapis.com`，不是 Safe Browsing）
2. 创建 API Key，API restrictions 限定 Web Risk
3. Project 需绑计费账号（免费额度内通常 $0）

本地先验证：

```bash
curl -s "https://webrisk.googleapis.com/v1/uris:search?threatTypes=MALWARE&uri=http%3A%2F%2Ftestsafebrowsing.appspot.com%2Fs%2Fmalware.html&key=$WEBRISK_API_KEY"
```

应返回带 `threat` 的 JSON，不是 403。

### 0.3 GitHub

仓库：`jevinwang-lb/portal-monitor-local`（若不同，改下方参数）。

你需要有该仓库的 Secrets 写权限。

---

## 1. 部署 bootstrap Stack

Bucket 名全局唯一，建议带账号 ID：

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
    GitHubRepo=portal-monitor-local \
    CreateOidcProvider=false
```

说明：

- `CreateOidcProvider=false`：账号里已有 `token.actions.githubusercontent.com` provider（2026-07-02 创建，Terraform 管理，`ClientIDList` 已含 `sts.amazonaws.com`），直接复用，模板不会去改它。设 `true` 会报 `EntityAlreadyExists`——更要紧的是那个 provider 是**全账号共享**的，其他仓库的 Actions 都依赖它，不要去纳管。
- `GitHubRefFilter` 不传，用模板默认值 `ref:refs/heads/main`：只有从 `main` dispatch 的 run 能假扮 Deploy Role。要部署哪个分支的代码由 workflow 的 `ref` 输入决定，与这里无关，见第 4 节。
- 信任策略同时匹配 GitHub OIDC 的**旧** `sub`（`repo:org/repo:…`）和**新**格式（`repo:org@ID/repo@ID:…`，2026-07-15 后新建的仓库）。若你改过模板里的这段，对已存在的 bootstrap Stack 再跑一次 §1 的 `cloudformation deploy` 即可更新 Role，不必重建 Bucket。
- `CAPABILITY_NAMED_IAM`：因为 Role 用了显式 `RoleName`。

看输出：

```bash
aws cloudformation describe-stacks \
  --region "$AWS_REGION" \
  --stack-name portal-monitor-bootstrap \
  --query 'Stacks[0].Outputs' \
  --output table
```

记下：

```text
StateBucketName   → 填 GitHub secret AWS_STATE_BUCKET
DeployRoleArn     → 填 GitHub secret AWS_DEPLOY_ROLE_ARN
```

---

## 2. 上传域名清单

首次 invoke 前必须有这份文件，否则 handler 会直接失败：

```bash
aws s3 cp domains.txt \
  "s3://${STATE_BUCKET}/portal-monitor/domains.txt" \
  --region "$AWS_REGION"
```

改域名以后只重新 `aws s3 cp`，不用重新部署 Lambda。

评估期建议先用少量域名（或测试 URL），不要一口气上百个。

---

## 3. 填 GitHub Secrets

仓库 → Settings → Secrets and variables → Actions → New repository secret：

| Secret | 值 |
| --- | --- |
| `AWS_DEPLOY_ROLE_ARN` | bootstrap 输出的 `DeployRoleArn` |
| `AWS_STATE_BUCKET` | bootstrap 输出的 `StateBucketName` |
| `WEBRISK_API_KEY` | GCP Web Risk API Key |
| `ALERT_WEBHOOK_URL` | Teams Webhook（评估期可先不填；`enable_webhook=false` 时不用） |

Region 写在 workflow 的 `env.AWS_REGION`，不是 Secret。

---

## 4. 部署 Lambda

前提：`.github/workflows/cd-lambda.yml` **必须存在于默认分支 `main`**。GitHub 的规定是 `workflow_dispatch` 只有文件在默认分支上才会出现 "Run workflow" 按钮，文件只在特性分支上时 Actions 页面根本不列出这个 workflow。

把 `aws/`、`.github/workflows/cd-lambda.yml`、`README.md` 合到 `main` 即可，不必合整个分支——`docker-publish.yml` 的 `paths` 只盯 `app/**`、`Dockerfile`、`requirements.txt`、`domains.txt`、`k8s/**`，上面三样都不在其中，所以不会连带触发镜像构建和 `cd-test-job.yml`。

Actions → **CD - Deploy Lambda** → Run workflow：

```text
Use workflow from   main                # 决定 OIDC sub，须匹配 GitHubRefFilter
ref                 feat/web-risk-api   # 决定打包哪份代码，与上面无关
enable_webhook      false               # 评估期务必 false，避免和 K8s 双份告警
```

这两个 ref 是不同的东西：下拉框选的分支决定 OIDC token 里的 `sub`（须匹配 bootstrap 的 `GitHubRefFilter`），而 `ref` 输入只交给 `actions/checkout` 决定打进 zip 的是哪个版本的 `monitor.py`。选错下拉框会在假扮 Role 那步报 `Not authorized to perform sts:AssumeRoleWithWebIdentity`。

成功标志：

- Stack `portal-monitor` 变成 `CREATE_COMPLETE` / `UPDATE_COMPLETE`
- Invoke 一步的日志里出现 `Found N domain(s)` 和各域名的 `SAFE` / `UNSAFE`
- S3 出现 `portal-monitor/status.json`

**没有 Web Risk key 时**，前面每步都会成功，只有最后的冒烟 invoke 会红，日志写 `ERROR: WEBRISK_API_KEY not configured`。这一步仍然验证了 OIDC 假扮、S3 上传、建栈、以及 Lambda 能读到 `domains.txt`；验证不到的是 Web Risk 调用和 `status.json` 回写。

看日志：

```bash
aws logs tail /aws/lambda/portal-monitor --follow --region "$AWS_REGION"
```

看状态：

```bash
aws s3 cp "s3://${STATE_BUCKET}/portal-monitor/status.json" - --region "$AWS_REGION"
```

---

## 5. 验收清单

- [ ] `aws sts get-caller-identity` 的 `Account` 是 `972910065688`
- [ ] bootstrap Stack 成功，Deploy Role ARN 已写入 Secrets
- [ ] `s3://…/portal-monitor/domains.txt` 存在
- [ ] Web Risk curl 能命中测试恶意 URL
- [ ] `CD - Deploy Lambda` 冒烟 invoke 成功（无 key 时预期失败，见第 4 节）
- [ ] `enable_webhook=false`（评估期）
- [ ] EventBridge Schedule 时区是 `Asia/Shanghai`，表达式每天 4 次

确认 Schedule：

```bash
aws scheduler get-schedule \
  --name portal-monitor \
  --region "$AWS_REGION" \
  --query '{State:State,Expr:ScheduleExpression,TZ:ScheduleExpressionTimezone}'
```

应类似：

```json
{
  "State": "DISABLED",
  "Expr": "cron(0 0,6,12,18 * * ? *)",
  "TZ": "Asia/Shanghai"
}
```

`State` 默认是 `DISABLED`，这样没有可用 key 的期间不会每天定时失败四次、白攒 CloudWatch 错误日志。拿到真 key、手动 invoke 验证通过后再打开：

```bash
aws cloudformation deploy \
  --region "$AWS_REGION" \
  --stack-name portal-monitor \
  --template-file aws/template.yaml \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides ScheduleState=ENABLED
```

其余参数不用重复传——`aws cloudformation deploy` 对未指定的参数沿用 Stack 现有值，所以后续 CD 也不会把 `ENABLED` 改回去。

---

## 6. 常见失败

| 现象 | 原因 |
| --- | --- |
| CD 假扮 Role 失败 `Not authorized to perform sts:AssumeRoleWithWebIdentity` | `AWS_DEPLOY_ROLE_ARN` 错；**Use workflow from** 不是 `main`（与 `GitHubRefFilter` 不符）；或 CloudTrail 里 `sub` 是 `repo:org@123/repo@456:…` 而 Role 仍是旧格式——更新 `aws/bootstrap.yaml` 后重跑 §1 deploy |
| `EntityAlreadyExists` OIDC | 设成了 `CreateOidcProvider=true`；该账号已有 provider，应保持 `false` |
| Invoke 报 `domains file not found` | 没上传 `domains.txt` |
| Invoke 报 `HTTP 403` / `SERVICE_DISABLED` | GCP 开的是 Safe Browsing，不是 Web Risk；或没绑计费 |
| Invoke 报 `WEBRISK_API_KEY not configured` | GitHub secret `WEBRISK_API_KEY` 为空 |
| `BucketAlreadyExists` | Bucket 名被别的账号占用，换一个后缀 |
| bootstrap 报 `AccessDenied` 且提到 SCP | Org 层 SCP 拦住了 `iam:CreateRole` 或显式 `RoleName`，需找 Org 管理员 |

---

## 7. 拆除（可选）

只删运行时 Stack，保留底座：

```bash
aws cloudformation delete-stack \
  --region "$AWS_REGION" \
  --stack-name portal-monitor
```

连底座一起拆。Bucket 因 `DeletionPolicy: Retain` **不会**随 Stack 删除，要手动清：

```bash
aws cloudformation delete-stack \
  --region "$AWS_REGION" \
  --stack-name portal-monitor-bootstrap
```

Bucket 开了版本控制，所以 **不能用 `aws s3 rb --force`**——它只删当前版本，历史版本和 delete marker 会留下，接着 `delete-bucket` 报 `BucketNotEmpty`。要按版本清空：

```bash
aws s3api list-object-versions \
  --bucket "$STATE_BUCKET" \
  --region "$AWS_REGION" \
  --output json \
  --query '{Objects: [Versions, DeleteMarkers][].{Key: Key, VersionId: VersionId}}' \
  > /tmp/portal-monitor-versions.json

aws s3api delete-objects \
  --bucket "$STATE_BUCKET" \
  --region "$AWS_REGION" \
  --delete file:///tmp/portal-monitor-versions.json

aws s3api delete-bucket \
  --bucket "$STATE_BUCKET" \
  --region "$AWS_REGION"
```

`delete-objects` 单次上限 1000 个版本。测试规模远低于此；若超了就重复前两步直到 `list-object-versions` 返回 `{"Objects": null}`。

拆完确认账号里没有残留：

```bash
aws s3api head-bucket --bucket "$STATE_BUCKET" --region "$AWS_REGION"        # 应 404
aws iam list-roles --query "Roles[?starts_with(RoleName,'portal-monitor')]"   # 应 []
aws scheduler list-schedules --region "$AWS_REGION" --group-name default      # 不应有 portal-monitor
aws logs describe-log-groups --log-group-name-prefix /aws/lambda/portal-monitor --region "$AWS_REGION"
```

共享的 GitHub OIDC Provider 不在拆除范围内，始终由 Terraform 持有。

---

## 文件对照

```text
aws/bootstrap.yaml     一次性：Bucket + OIDC + Deploy Role
aws/template.yaml      日常：Lambda + Scheduler + 执行角色
aws/lambda_handler.py  Lambda 入口，代理 S3 ↔ /tmp
.github/workflows/cd-lambda.yml   日常 CD
```
