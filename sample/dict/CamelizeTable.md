# CamelizeTable

## 概要

<details>
<summary><strong>テーブル定義</strong></summary>

```sql
CREATE TABLE `CamelizeTable` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `created` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
```

</details>

## カラム一覧

| 名前      | タイプ      | デフォルト値       | Nullable | Extra Definition | 子テーブル      | 親テーブル      | コメント     |
| ------- | -------- | ------------ | -------- | ---------------- | ---------- | ---------- | -------- |
| id      | bigint   |              | false    | auto_increment   |            |            |          |
| created | datetime |              | false    |                  |            |            |          |

## 制約一覧

| 名前      | タイプ         | 定義               |
| ------- | ----------- | ---------------- |
| PRIMARY | PRIMARY KEY | PRIMARY KEY (id) |

## INDEX一覧

| 名前      | 定義                           |
| ------- | ---------------------------- |
| PRIMARY | PRIMARY KEY (id) USING BTREE |

## ER図

![er](CamelizeTable.svg)
