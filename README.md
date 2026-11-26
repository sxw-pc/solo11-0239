# 租户资源承诺所

离线的共享节点资源控制面。权益账本、节点预留和借用结算各自可运行，也能以事件引用形成跨系统承诺。所有状态存 SQLite；输入 fixture 为 JSON 事件序列，报告包含原始事件与当前业务状态。

## 使用

`python -m cloudquota.cli all fixtures/demo.json --db demo.sqlite`

`python -m cloudquota.cli budget fixtures/budget_normal.json --db budget.sqlite`

`python -m unittest discover -s tests -v`

依赖仅 Python 标准库。脚本首次打开数据库时创建表；删除 demo.sqlite 可重置。每个 `actions` 元素有 `op` 与 `args`。业务失败以结果码记录，输入格式错误以异常退出。

## 业务边界

预算修订不会追删运行中的旧承诺。节点席位和租户权益均通过 SQLite 即时事务保护。借款到期阻断新借入，回收只释放尚未启动的可中断预留。工作负载组缩容须保留最小存活副本。额度来源归属在基础预算、授权和贷款间固定唯一来源。

后续边界：多方预算审批、节点故障代偿、抢占补偿、保留券交易、成本分摊、资源争议仲裁、异地容量承诺。当前版本不实现这些流程。

### 跨集群权益转移（`cloudquota/cluster_transfer.py`）

每笔调拨显式登记租户、来源/目标集群、来源权益批次（基础预算、授权或贷款，按类别独立核算，永不混算）与有效窗，并在 prepare/commit 两个时点分别核对两个集群的容量证明代次。流程为可恢复 saga：`request → prepare（来源冻结权益+目标预留节点席位）→ target_ack（单事务双账扣增）→ deliver`；目标拒绝、确认丢失或节点缩容时回滚已冻结的权益与席位。未启动预留只有在可中断、租期重叠、固定来源一致且取得客户释放签收后才能让出席位；已启动副本的来源不可转移。客户签收、席位、交付、通知与账单均为只追加记录，迟到回执按 `late:` 留证但不覆盖已交付结果；无法走转移路径时由独立新购权益兜底，并明确记录原时限失约与补偿。命令前缀 `transfer.`（cluster/node/lot/request/signoff/prepare/target_ack/deliver/cancel/fallback_purchase/start_purchase）。
