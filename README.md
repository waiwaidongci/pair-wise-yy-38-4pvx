# 水库防汛调度与操作确认

根据库位、入库流量、下游警戒和施工限制生成复核授权的泄洪指令。水情快照、调度指令和复核授权三者联动：快照更新后旧授权自动失效并退回待复核。

## 模块结构

- `app.py`：参数解析、依赖组装和HTTP服务启动。
- `src/domain.py`：数据结构、错误、状态和基础校验。
- `src/rules.py`：状态机、角色矩阵、优先级、期限、快照失效规则和关闭不变量。
- `src/repository.py`：SQLite建表、事务、版本控制、幂等键、崩溃恢复和审计链。
- `src/service.py`：权限检查、用例编排、并发控制、快照联动和审计。
- `src/http_api.py`：JSON路由和统一错误响应（含`blockers`阻塞项）。
- `src/audit.py`：UTC时间和SHA-256审计事件。
- `static/index.html`：最小演示页。
- `tests/`：完整流程、规则、失败和快照联动测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8315
```

默认端口为`8315`，首次启动自动建库。使用`X-Actor`和`X-Role`请求头传递身份。

## 主要接口

- `GET /health`
- `GET /api/items`
- `POST /api/items`
- `GET /api/items/{id}`
- `POST /api/items/{id}/records`
- `POST /api/items/{id}/transition`，必须提交`expected_version`，可带`idempotency_key`（或`Idempotency-Key`请求头）
- `POST /api/snapshots`，发布水情快照（duty_officer / chief_engineer）
- `GET /api/snapshots`、`GET /api/snapshots/current`
- `GET /api/audit`

允许角色：duty_officer, chief_engineer, dispatcher, viewer。库位超过汛限或入库流量上升时提升紧迫度；授权前必须有复核记录，执行后仍要闭环现场反馈。

## 快照—指令—授权联动

- 指令在复核（`checked`）时原子绑定当前快照版本；授权（`authorized`）时在同一事务内校验快照未过期，过期则拒绝并返回`blockers`。
- 发布新快照后，处于`checked`/`authorized`的指令在同一事务内退回`draft`待复核，授权记录置为`invalidated`并记录失效原因；`executed`/`closed`指令不倒退。
- 审计事件：`invalidate`（失效原因、原快照版本、新快照版本、变化字段）、`snapshot`（受影响与跳过的指令）、`blocked`（阻塞项、快照版本）、`recovery`（重启回收的未完成提交）、`idempotent_replay`（幂等回放）。

## 并发、幂等与恢复

- 两个终端同时提交时按`expected_version`乐观并发控制，只接受当前版本，失败方收到409版本冲突。
- 转换接口支持幂等键：业务写入与键置完成在同一事务提交；一笔失败后凭同一幂等键重试不会重复放水，已完成的键直接回放首次结果。
- 写入中断重启后，残留的`pending`提交自动回收为可重试并写`recovery`审计；客户端凭同一幂等键重试即可完成。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
