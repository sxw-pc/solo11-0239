# 租户资源承诺所

离线的共享节点资源控制面。权益账本、节点预留和借用结算各自可运行，也能以事件引用形成跨系统承诺。所有状态存 SQLite；输入 fixture 为 JSON 事件序列，报告包含原始事件与当前业务状态。

## 使用

`python -m cloudquota.cli all fixtures/demo.json --db demo.sqlite`

`python -m cloudquota.cli budget fixtures/budget_normal.json --db budget.sqlite`

`python -m cloudquota.cli settle fixtures/settle_normal.json --db settle.sqlite`

`python -m unittest discover -s tests -v`

依赖仅 Python 标准库。脚本首次打开数据库时创建表；删除 demo.sqlite 可重置。每个 `actions` 元素有 `op` 与 `args`。业务失败以结果码记录，输入格式错误以异常退出。

## 业务边界

预算修订不会追删运行中的旧承诺。节点席位和租户权益均通过 SQLite 即时事务保护。借款到期阻断新借入，回收只释放尚未启动的可中断预留。工作负载组缩容须保留最小存活副本。额度来源归属在基础预算、授权和贷款间固定唯一来源。

## 月度关账（settle）

`cloudquota/cost_settlement.py` 面向固定账期（如第 0 至 60 分钟）做成本分摊与客户结算。金额一律为整数微元（1 元 = 1_000_000）。客户账单按费率版本 × 实际履约时段（保留 / 运行）计算；电表原件只用于平台侧对账：计量总额 = 租户节点费用 + 平台损失（确认事故 + 残余）。预留未启动按合同选项收承诺费（reservation）或免费且容量可转售（usage）；事故金额由平台自担，永不进入客户行；贷款收益单列、本金永不出现在账单；已释放席位计费止于释放原件。已出具账单不可被迟到原件静默覆盖，只能凭有因果引用的补充 / 冲正凭证更正；异议、部分付款与下月结转均按实际收讫计算。重叠计量切片在录入时拒绝或经 supersede 链替换，绝不重复分摊。

后续边界：跨集群权益转移、多方预算审批、节点故障代偿、抢占补偿、保留券交易、资源争议仲裁、异地容量承诺。当前版本不实现这些流程。
