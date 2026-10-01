# aolog：可落盘、可独立审计的追加 JSON 日志

实现一个只依赖 Python 标准库的追加日志服务与独立审计命令。

## 核心性质

- 记录先规范化为 UTF-8 JSON：对象键按 Unicode 码位排序，拒绝重复键、非有限数字和非法 Unicode。
- 每条日志记录落盘为：
  - 16 字节固定帧头：magic/version/flags/reserved/payload length/header CRC32；
  - 规范化 JSON payload；
  - 32 字节 `SHA-256(header || payload)` 校验值。
- Merkle 树使用不同域前缀：
  - 叶节点：`SHA-256(0x00 || record_bytes)`；
  - 内部节点：`SHA-256(0x01 || left_hash || right_hash)`；
  - 空树根为 `SHA-256("")`。
- 树头以原子 rename 发布，包含 `tree_size` 和 `root_hash`。
- 服务支持批量追加、按序号读取记录、包含证明、旧树头到新树头的一致性证明。
- 所有追加在同一把锁内排序，批内顺序固定，返回唯一连续序号。
- 重启时：
  - 完整帧头但 payload/checksum 未写完：视为未完成尾记录，截断；
  - 不足 16 字节的尾部帧头：截断；
  - 已完整写入的帧若 magic、CRC、长度或 checksum 错误，即使位于尾部也报 `LogCorruptionError`，绝不跳过。
- `tree-head.json` 与日志不一致时报 `TreeHeadConflictError`。崩溃发生在记录 fsync 后、树头发布前时，重启会保留完整记录并重新发布对应树头。

## HTTP API

- `POST /v1/append`
  - body: `{"records":[ ... ]}`，也接受顶层 JSON 数组。
- `GET /v1/head`
- `GET /v1/records/{index}`
- `GET /v1/proof?index={i}&size={n}`
  - `size` 缺省为当前已发布树大小。
- `GET /v1/consistency?old_size={m}&new_size={n}`

所有 JSON 响应同样是规范化 JSON。记录接口直接返回规范化后的 JSON 字节。

## 运行

无需第三方依赖：

```bash
PYTHONPATH=/workspace python3 -m aolog serve --directory ./data --port 8080
```

追加与读取：

```bash
PYTHONPATH=/workspace python3 -m aolog append --base http://127.0.0.1:8080 '{"n":1}' '{"n":2}'
PYTHONPATH=/workspace python3 -m aolog head --base http://127.0.0.1:8080
PYTHONPATH=/workspace python3 -m aolog record 1 --base http://127.0.0.1:8080
PYTHONPATH=/workspace python3 -m aolog proof 1 --base http://127.0.0.1:8080
PYTHONPATH=/workspace python3 -m aolog consistency 1 2 --base http://127.0.0.1:8080
```

## 独立审计

```bash
PYTHONPATH=/workspace python3 -m aolog audit \
  --base http://127.0.0.1:8080 \
  --state ./audit-state.json
```

审计命令不读取服务的“验证通过”结论：

1. 读取本地保存的旧 `(tree_size, root_hash)`；首次审计旧树为空树。
2. 获取服务当前树头。
3. 获取一致性证明，并在本地重建旧根和新根。
4. 下载所有新增记录，在本地重新规范化和计算叶哈希。
5. 获取每条记录的包含证明，并在本地重建当前根。
6. 全部通过后才原子更新本地审计状态；任何失败返回非零退出码且不推进状态。

## 崩溃注入测试钩子

服务可在“所有记录写入并 fsync 后、树头发布前”立即退出：

```bash
PYTHONPATH=/workspace python3 -m aolog serve \
  --directory ./data --crash-at after_records
```

测试中通过子进程直接构造 `AppendOnlyStore(..., crash_at="after_records")` 覆盖该崩溃点。

## 测试

```bash
PYTHONPATH=/workspace python3 -m unittest discover -s tests -v
```

测试覆盖：

- 规范化 JSON、重复键和非法 UTF-8；
- 1..64 叶小树与独立递归建树结果逐一对拍；
- 所有小规模叶索引的包含证明及篡改拒绝；
- 所有小规模旧前缀的一致性证明及非前缀根拒绝；
- 并发批量追加的唯一连续顺序；
- 尾部未完成帧截断、中段/完整尾帧损坏报错；
- 树头篡改报错；
- 记录 fsync 后、树头发布前崩溃后的恢复；
- HTTP 端到端审计，以及审计器拒绝服务提供的篡改记录。
