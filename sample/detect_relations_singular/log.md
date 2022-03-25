# log

## Description

Auditログ

<details>
<summary><strong>Table Definition</strong></summary>

```sql
CREATE TABLE `log` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `post_id` bigint DEFAULT NULL,
  `comment_id` bigint DEFAULT NULL,
  `comment_star_id` bigint DEFAULT NULL,
  `payload` text,
  `created` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='Auditログ'
```

</details>

## Columns

| Name | Type | Default | Nullable | Extra Definition | Children | Parents | Comment |
| ---- | ---- | ------- | -------- | ---------------- | -------- | ------- | ------- |
| id | bigint |  | false | auto_increment |  |  |  |
| user_id | int |  | false |  |  | [user](user.md) |  |
| post_id | bigint |  | true |  |  | [post](post.md) |  |
| comment_id | bigint |  | true |  |  | [comment](comment.md) |  |
| comment_star_id | bigint |  | true |  |  | [comment_star](comment_star.md) |  |
| payload | text |  | true |  |  |  |  |
| created | datetime |  | false |  |  |  |  |

## Constraints

| Name | Type | Definition |
| ---- | ---- | ---------- |
| PRIMARY | PRIMARY KEY | PRIMARY KEY (id) |

## Indexes

| Name | Definition |
| ---- | ---------- |
| PRIMARY | PRIMARY KEY (id) USING BTREE |

## Relations

![er](log.svg)
