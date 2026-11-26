# 集群升阶兼容闸台

基础设施 / 云原生离线业务系统。Python 标准库与 SQLite 即可运行，不需要集群或云凭据。

## 三个业务入口

- `inventory` 记录节点架构、故障域、版本代际和 API 使用事实。观测过期、能力缺失或仍在使用废弃 API 时，节点不能进入升级波次。低代次扫描不能覆盖新事实。
- `migration` 比较旧新 API 配置的有效行为，记录工作负载配置基线、迁移结论和回滚锚点。迁移成功更新 API 使用状态，失败冻结波次；回滚恢复配置与旧 API 引用。
- `wave` 固定目标版本、父波次及故障域预算。释放时使用节点持久化的故障域；完成时要求同一节点代际和目标版本的健康探针。

三个入口各有状态表、独立命令、正常和失败样例。决定及其输入、版本存入 `evidence`；`replay` 从事件重建业务表并逐表比较。

## 退役介质的客户数据保管交割

节点升阶完成只覆盖节点版本与能力, 不覆盖旧磁盘/备份卷上哪家客户的数据仍可恢复。`media_custody` 在三个入口之外建立独立的介质-对象-块-密钥-法令事实链, 由 `erasure_proof` 做纯判定:

- 法令核对: 删除令/保全令必须核对主体、数据范围、生效与到期、签发权(客户只能发删除令, 法院才能发保全令)和实际介质位置。
- 物理事实优先: 目录项删除、资产表退役标记、应用层密钥注销都不是不可恢复证明; 块级去重/压缩/统一密钥使逻辑对象与物理字节不是一对一, 必须按块核算全部备份、缓存与离线镜像。仅按对象号签发的擦除回单不能作为物理删除依据。
- 路径一 `reencrypt`: 乙方对象迁入独立密钥卷并逐对象核验原文哈希与顺序后, 旧共享卷与统一密钥全部销毁, 方可出具甲方删除证并向法院交付乙方。
- 路径二 `sealed`: 原卷送入有独立监管的封闭托管, 甲方片段必须从全部物理副本(含托管卷)见证剔除; 若共享块无法分离甲片段, 案件停在 `halted`, 只能请法院改变保全方式, 不出具假删除证。
- 外部事实: 存储商擦除回单、托管收件、法院收件、客户删除证均以带签名时间的回单/证书行登记。晚到漏盘使已发证书作废并换发更正版, 断电重试走幂等返回, 不重复出具完成证书; 存储商拒绝擦除会把案件置为阻断态。


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
