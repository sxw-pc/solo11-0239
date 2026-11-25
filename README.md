# 租户资源承诺所

离线的共享节点资源控制面。权益账本、节点预留和借用结算各自可运行，也能以事件引用形成跨系统承诺。所有状态存 SQLite；输入 fixture 为 JSON 事件序列，报告包含原始事件与当前业务状态。

## 使用

`python -m cloudquota.cli all fixtures/demo.json --db demo.sqlite`

`python -m cloudquota.cli budget fixtures/budget_normal.json --db budget.sqlite`

`python -m unittest discover -s tests -v`

依赖仅 Python 标准库。脚本首次打开数据库时创建表；删除 demo.sqlite 可重置。每个 `actions` 元素有 `op` 与 `args`。业务失败以结果码记录，输入格式错误以异常退出。

## 业务边界

预算修订不会追删运行中的旧承诺。节点席位和租户权益均通过 SQLite 即时事务保护。借款到期阻断新借入，回收只释放尚未启动的可中断预留。工作负载组缩容须保留最小存活副本。额度来源归属在基础预算、授权和贷款间固定唯一来源。

后续边界：跨集群权益转移、多方预算审批、节点故障代偿、抢占补偿、保留券交易、成本分摊、资源争议仲裁、异地容量承诺。当前版本不实现这些流程。
