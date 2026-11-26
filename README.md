# 租户资源承诺所

离线的共享节点资源控制面。权益账本、节点预留和借用结算各自可运行，也能以事件引用形成跨系统承诺。所有状态存 SQLite；输入 fixture 为 JSON 事件序列，报告包含原始事件与当前业务状态。

## 使用

`python -m cloudquota.cli all fixtures/demo.json --db demo.sqlite`

`python -m cloudquota.cli budget fixtures/budget_normal.json --db budget.sqlite`

`python -m unittest discover -s tests -v`

依赖仅 Python 标准库。脚本首次打开数据库时创建表；删除 demo.sqlite 可重置。每个 `actions` 元素有 `op` 与 `args`。业务失败以结果码记录，输入格式错误以异常退出。

## 业务边界

预算修订不会追删运行中的旧承诺。节点席位和租户权益均通过 SQLite 即时事务保护。借款到期阻断新借入，回收只释放尚未启动的可中断预留。工作负载组缩容须保留最小存活副本。额度来源归属在基础预算、授权和贷款间固定唯一来源。

### 多方预算审批与紧急授权（`cloudquota/approval.py`，命令前缀 `approval.` / `emergency.`）

大额扩容不再由一次直接的 `budget.revise` 生效。每份预算申请（`approval.submit`）固定租户、原修订号、目标 CPU/内存、生效窗、资金账户和申请人，并得到绑定申请编号与全部固定条款的 SHA-256 摘要；签名（`approval.sign` / `approval.sign_as`）是审批席位对该摘要的 HMAC，因此申请内容被修改或把签名挪到重新基于新版本发起的另一份申请都会得到 `bad_signature` / `digest_mismatch`。

计票（`approval.tally` / `commit`）只承认同时满足以下条件的签名：席位在授权范围（额度上限、租户、财务/容量域）与有效任期内；代理在签署时刻未被撤销（撤销原件以 `revoked_at`/事件号保留，签署时间不早于撤销时刻即 `delegation_revoked`，离职后的签名为 `seat_tenure_ended`）；实际签署人与席位持有人均不属于“申请人—受益租户控制人”的利益闭包，相互代理、共同控制或关联关系会合并为同一利益方；同一自然人经多个重叠席位或代理签署只计一个独立人数。正式大额扩容默认须两名无利益关系审批人，并分别覆盖财务与容量负责人。

`approval.commit` 在单事务内再次校验摘要、票数和版本：当前预算修订必须仍等于申请固定的原修订号；期间若已有另一合法修订（如修订 5）生效，申请被判为 `base_revision_conflict`/拒绝，不能跳过冲突版本写入。通过后才以原申请内容一次性写入 `base+1` 修订，并在 `budget_authority` 中记录生效人、权限类型（`approved_application`/`direct`）、审批人、摘要与时刻。直接调用 `budget.revise` 的修订同样会以 `direct` 权限留痕。旧版上已经获得的运行预留保留历史，不被追改。

紧急路径：值班负责人先 `emergency.incident` 独立确认事故（确认人不得是申请人且须具 `duty_lead` 角色），再 `emergency.authorize` 给予有硬上限（默认 CPU/内存各 4）、有 `expires_at` 的临时增量。紧急额度只能让可中断预留（`reserve.place`）补足相对现行合法预算的边际缺口，预留的唯一资金来源记为 `emergency:<id>`，边际占用记入 `emergency_draws`；超出上限为 `emergency_quota_exhausted`，非可中断请求为 `emergency_interruptible_only`，超过期限为 `emergency_window_exceeded`/`emergency_expired`。`emergency.expire` 自动失效授权并中断、处置到期临时席位。事后 `emergency.review` 由独立复核人执行：通过则 `review_passed`；失败则 `review_failed` 并在 `reservation_holds` 为租户置停留，`reserve.place` 对所有新预留返回 `new_reservations_blocked`，已经发生的使用、draw、处置、追责值班负责人和只追加审计均保留，绝不把历史改写成从未发生。`approval.audit_report` 与 `capacity_compliance` 给出版本权限、被拒申请、无效签名、紧急额度使用/复核/处置、停留以及“未授权容量使用”的核对结果；所有新表都纳入 `store.report` 的行级审计触发器与 `verify_replay` 重放一致性校验。

后续边界：跨集群权益转移、节点故障代偿、抢占补偿、保留券交易、成本分摊、资源争议仲裁、异地容量承诺。当前版本不实现这些流程。
