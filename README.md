# 水库防汛调度与操作确认

根据库位、入库流量、下游警戒和施工限制生成复核授权的泄洪指令。

水情、施工限制与复核授权联动：授权必须钉住当前水情/施工快照版本；快照一更新，旧授权立即失效并退回待复核，已执行指令不可倒退（作为阻塞项记入审计）；泄洪执行凭幂等键重试不重复放水；写入中断重启后未完成提交自动恢复。

## 模块结构

- `app.py`：参数解析、依赖组装、HTTP服务启动和启动恢复。
- `src/domain.py`：数据结构、错误、状态和基础校验。
- `src/rules.py`：状态机、角色矩阵、快照规则、优先级、期限和关闭不变量。
- `src/repository.py`：SQLite建表、事务、版本控制、快照、幂等操作、崩溃恢复和审计链。
- `src/service.py`：权限检查、用例编排、并发控制、快照失效、幂等执行和审计。
- `src/http_api.py`：JSON路由和统一错误响应。
- `src/audit.py`：UTC时间和SHA-256审计事件。
- `static/index.html`：最小演示页。
- `tests/`：完整流程、规则、失败和快照/幂等/恢复测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8315
```

默认端口为`8315`，首次启动自动建库，启动时自动恢复未完成的调度提交。使用`X-Actor`和`X-Role`请求头传递身份。

## 主要接口

- `GET /health`
- `GET /api/items`
- `POST /api/items`
- `GET /api/items/{id}`
- `POST /api/items/{id}/records`
- `POST /api/items/{id}/transition`，必须提交`expected_version`（乐观锁，两个终端同时提交只接受当前版本）
- `POST /api/items/{id}/execute`，泄洪执行，必须提交`expected_version`和`idempotency_key`
- `GET /api/snapshots`、`GET /api/snapshots/current`
- `POST /api/snapshots`，提交`kind`(`water`/`restriction`)、`payload`、`note`
- `GET /api/operations/{idempotency_key}`，查询幂等操作状态
- `GET /api/audit`

允许角色：duty_officer, chief_engineer, dispatcher, viewer。库位超过汛限或入库流量上升时提升紧迫度；授权前必须有复核记录，执行后仍要闭环现场反馈。

## 快照、授权与幂等

- **快照版本**：水情(`water`)或施工限制(`restriction`)快照带全局单调版本号；授权通过时指令钉住当前快照版本(`snapshot_version`)。
- **失效退回**：新快照写入后，所有依赖旧快照的`authorized`指令在同一事务内退回`checked`（待复核），审计记录失效原因、新旧快照版本和阻塞项；已执行/已关闭指令不可倒退，仅作为阻塞项记录。
- **乐观并发**：状态更新带`WHERE version=?`条件，并发提交只有一个成功，失败者收到`409`。
- **幂等执行**：`/execute`凭`idempotency_key`去重。同键重试返回首次结果(`replayed=true`)，不重复放水；异键重复执行已完成指令被拒绝；失败后可凭同一幂等键重试。
- **崩溃恢复**：执行操作先登记`pending`再提交。重启时`recover()`自动续跑：指令已执行的补提交标记、未完成的继续执行、授权已失效的置失败，已执行指令绝不倒退。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
