# 集群升阶兼容闸台

基础设施 / 云原生离线业务系统。Python 标准库与 SQLite 即可运行，不需要集群或云凭据。

## 三个业务入口

- `inventory` 记录节点架构、故障域、版本代际和 API 使用事实。观测过期、能力缺失或仍在使用废弃 API 时，节点不能进入升级波次。低代次扫描不能覆盖新事实。
- `migration` 比较旧新 API 配置的有效行为，记录工作负载配置基线、迁移结论和回滚锚点。迁移成功更新 API 使用状态，失败冻结波次；回滚恢复配置与旧 API 引用。
- `wave` 固定目标版本、父波次及故障域预算。释放时使用节点持久化的故障域；完成时要求同一节点代际和目标版本的健康探针。

三个入口各有状态表、独立命令、正常和失败样例。决定及其输入、版本存入 `evidence`；`replay` 从事件重建业务表并逐表比较。

## 运行

在仓库根目录执行：

```sh
python -m cloudlab demo --db demo.sqlite
python -m cloudlab report --db demo.sqlite
python -m cloudlab replay --db demo.sqlite
python -m unittest discover -s tests -v
```

单入口样例：

```sh
python -m cloudlab inventory --db isolated.sqlite --fixture fixtures/inventory_ok.json
python -m cloudlab inventory --db isolated.sqlite --fixture fixtures/inventory_fail.json
python -m cloudlab migration --db isolated.sqlite --fixture fixtures/migration_ok.json
python -m cloudlab wave --db isolated.sqlite --fixture fixtures/wave_ok.json
```

`migration_ok` 的回滚锚点与 `wave_ok` 的释放步骤引用 `inventory_ok` 创建的节点。按上面的顺序使用同一个新数据库，或运行 `demo`。每个入口另有对应的 `_fail.json`；命令返回具体决定和阻断原因。

## 可复现的交互

1. 已迁移的废弃 API 引用不再阻断节点验证；回滚后重新进入阻断清单。
2. 同一故障域的第二台节点在预算为一时不能释放升级，即使请求伪造地域或扩大预算。
3. 升级释放占用预算，目标版本健康探针通过后才可完成；失败探针、节点重建或无效回滚锚点均保留阻断证据。

## 风险申请、独立审批与生效版本（`wave_approval`）

`risk_request.propose` 锁定服务、原额度版本（`base_version`）、目标额度、区位、维护窗和受益客户，并生成 canonical 摘要；`risk_sign.sign` 把外部/设备签名固定到该摘要。`wave_approval` 不把“两个签名”当成“两个独立责任人”：

- 席位有任期、绝对额度上限/增幅、区位与服务范围；代理授权有范围、生效授予时间和**生效撤销时间**（回单可以晚到，权限按签署时刻与生效时间判定）。
- 技术账户、法人账户和多层代理链都回溯到同一**最终控制人**；同一控制人名下的多签只算一个独立责任组。
- `activate` 先做乐观版本比较：申请锁定的 `base_version` 必须等于 `(service, zone)` 当前预算头，否则返回 `stale_base_version`/`competing_revision`，旧申请不能越过先提交的合法修订。
- 正式批准要求足够数量、角色齐备且控制人互异的合格签署，随后追加一条不可变 `budget_revisions`；`wave` 释放时以 `min(计划额度, 生效额度+有效紧急额度)` 为准，并为每个 `transition` 写 `release_attributions`。
- 值班负责人凭已核实事故单可签发 `issue_emergency`：最多 `+1`、必须有 `valid_until`、由客户代表 `review_emergency`。到期或复核失败后新占用被挡（`emergency_permit_expired` / `emergency_review_failed`），已发生的释放与签发人责任保留。
- `accountability(wave_id=...)` 输出每份已实施额度由哪些互异控制人、经何种文书（正式修订/紧急许可）共同负担。

签署流水 `risk_signatures`、`approval_ledger` 与 `budget_revisions` 由 SQLite 触发器禁止 UPDATE/DELETE；迟到撤销只改变后续资格判定，不涂改旧外部签署和已发生的升级。完整夜场 R（第 18/19/20/21/22 分钟事实、紧急路线与重基线正式路线、断网补签、竞争修订）见 `tests/test_wave_approval.py`。

```sh
python -B -m unittest discover -s tests -q
```
