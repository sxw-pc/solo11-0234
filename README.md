# 集群升阶兼容闸台

基础设施 / 云原生离线业务系统。三个入口各自维护不同的业务对象、状态和持久化实体，不需要 Kubernetes 集群、云凭据或外部服务。Python 标准库和 SQLite 即可运行。

## 业务边界

- **能力盘点**：节点能力与 API 使用清单。决定某节点及工作负载能否进入目标版本波次；状态为observed 到 verified 或 stale。持久化实体：node_capability、api_usage。能力盘点变化会阻断升级波次和迁移验收
- **升级波次**：有序升级波次与可用性预算。决定当前波次能否释放节点升级；状态为planned 到 eligible 到 applying 到 complete 或 blocked。持久化实体：upgrade_wave、node_transition。波次结果决定迁移验收所用版本基线
- **兼容迁移**：API 迁移记录与回退证据。决定目标版本上工作负载行为是否已完成兼容迁移；状态为proposed 到 verified 或 rejected，失败转 rollback_pending。持久化实体：migration_case、rollback_record。迁移失败会冻结后续波次并触发回退

所有命令用 SQLite 的 IMMEDIATE 事务提交状态，并保存输入、输出、版本和顺序证据。拒绝也进入 evidence 台账；重复或迟到事件不能默默改写已经成立的承诺。业务表与台账可用 replay 命令从原始事件重建并逐表核对。

## 快速运行

在仓库根目录执行：

```sh
python -m cloudlab demo --db demo.sqlite
python -m cloudlab report --db demo.sqlite
python -m cloudlab replay --db demo.sqlite
python -m unittest discover -s tests -v
```

单独执行一个子系统的 fixture：

```sh
python -m cloudlab inventory --db isolated.sqlite --fixture fixtures/inventory_ok.json
python -m cloudlab inventory --db isolated.sqlite --fixture fixtures/inventory_fail.json
```

每个入口提供 *_ok.json 和 *_fail.json。若步骤需要上游承诺，先在同一个数据库依次执行前置入口；demo 展示三者的完整顺序。CLI 返回 decision 和具体阻断 reason。重新演示时使用新的数据库文件，避免幂等键与旧实验相撞。

## 代码导航

- `cloudlab/store.py`：SQLite 初始化、事务、原始输入与决策证据、回放逐表核验。
- `cloudlab/inventory.py`：节点能力与 API 使用清单 的业务状态机和独立命令。
- `cloudlab/wave.py`：有序升级波次与可用性预算 的业务状态机和独立命令。
- `cloudlab/migration.py`：API 迁移记录与回退证据 的业务状态机和独立命令。
- `cloudlab/__main__.py`：JSON fixture CLI、演示和证据报告。
- `tests/test_workflows.py`：正常、失败、跨系统状态和证据回放测试，运行时打印 `cloudlab.__file__`。

## 数据和恢复约束

1. 某节点目标运行时能力观测过旧，虽声称兼容仍不能进波次；重新盘点并验证后才放行。 两个子系统的持久化结论相互改变。某节点目标运行时能力观测过旧，虽声称兼容仍不能进波次；重新盘点并验证后才放行。 失败或迟到事实保留可重算的阻断证据
2. 同一故障域的两个节点同时申请升级，尽管各自可用性检查通过，合并波次会破坏服务副本预算。 两个子系统的持久化结论相互改变。同一故障域的两个节点同时申请升级，尽管各自可用性检查通过，合并波次会破坏服务副本预算。 失败或迟到事实保留可重算的阻断证据
3. 旧新 API 转换样例字段存在但默认行为不同，迁移拒绝并冻结后续波次；回退必须找到配对配置锚点。 两个子系统的持久化结论相互改变。旧新 API 转换样例字段存在但默认行为不同，迁移拒绝并冻结后续波次；回退必须找到配对配置锚点。 失败或迟到事实保留可重算的阻断证据

这三个入口的业务结果分别可观察；只有持久化证据和相关实体的版本、身份一致，才能继续改变下游结论。
