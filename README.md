# 集群升阶兼容闸台

基础设施 / 云原生离线业务系统。Python 标准库与 SQLite 即可运行，不需要集群或云凭据。

## 三个业务入口

- `inventory` 记录节点架构、故障域、版本代际和 API 使用事实。观测过期、能力缺失或仍在使用废弃 API 时，节点不能进入升级波次。低代次扫描不能覆盖新事实。
- `migration` 比较旧新 API 配置的有效行为，记录工作负载配置基线、迁移结论和回滚锚点。迁移成功更新 API 使用状态，失败冻结波次；回滚恢复配置与旧 API 引用。
- `wave` 固定目标版本、父波次及故障域预算。释放时使用节点持久化的故障域；完成时要求同一节点代际和目标版本的健康探针。

三个入口各有状态表、独立命令、正常和失败样例。决定及其输入、版本存入 `evidence`；`replay` 从事件重建业务表并逐表比较。

## 物理计量归属（付款与开票两本账）

`physical` 子系统在页摘要之上建立可用于付款和开票的物理归属，供应商付款与客户开票各自独立授权、独立事务、独立幂等：

- 采录先验证页摘要、时钟校准链和宿主序列链与原始字节相连；门户复扫经宿主别名（含机箱换标历史）归一到同一物理序列号，按“物理宿主 + 分钟 + 容器”去重，重复扫描不产生新算力。
- 结算前整批物理总量必须与独立 CPU 控制器的运行计数逐宿主逐分钟守恒，偏差或缺计数则整批资金单据阻断。
- 每台物理宿主每分钟的实际核秒只生成一笔供应商应付，付款一次；客户账单只开给在所有仍相容迁移历史中都确属同一租户的核秒。门户租户标签与页到达顺序不是归属证明，只有锚定的所有权声明或条码完整、且锚定升级窗虚机迁移的凭条才算证据；条码缺末四位等存疑核秒保持未分清，绝不按比例猜分。
- 物理总量已定而客户未分清时，供应商仍按确定总量付款。未分清部分按事先签准的指令二选一：`loss_provision` 由运营方自有资金建损失准备，租户不作外部付款；`group_deposit` 由集团按预付担保实际汇入可退保证金，平台记为负债而非使用收入。
- 银行批次发出后旧付款、旧发票不可覆盖；晚到迁移凭条只产生追索、补票或可追溯冲正（原单据保留，调整凭证回指原件）。保证金路线先抵扣或退款再开最终使用发票，任何一步都不双收。`rebuild` 可在审计或断电重试时仅凭 `evidence` 重建两本实际账。


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
