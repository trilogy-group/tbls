# CamelizeTable

## Description

<details>
<summary><strong>Table Definition</strong></summary>

```sql
CREATE TABLE `CamelizeTable` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `created` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
```

</details>

## Columns

| Name | Type | Default | Nullable | Extra Definition |
| ---- | ---- | ------- | -------- | ---------------- |
| id | bigint |  | false | auto_increment |
| created | datetime |  | false |  |

## Constraints

| Name | Type | Definition |
| ---- | ---- | ---------- |
| PRIMARY | PRIMARY KEY | PRIMARY KEY (id) |

## Indexes

| Name | Definition |
| ---- | ---------- |
| PRIMARY | PRIMARY KEY (id) USING BTREE |

## Relations

![er](CamelizeTable.png)
