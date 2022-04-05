# comment_star

## Description

<details>
<summary><strong>Table Definition</strong></summary>

```sql
CREATE TABLE `comment_star` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `comment_post_id` bigint NOT NULL,
  `comment_user_id` int NOT NULL,
  `created` timestamp NOT NULL,
  `updated` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `user_id` (`user_id`,`comment_post_id`,`comment_user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
```

</details>

## Columns

| Name | Type | Default | Nullable | Extra Definition | Children | Parents |
| ---- | ---- | ------- | -------- | ---------------- | -------- | ------- |
| id | bigint |  | false | auto_increment | [log](log.md) |  |
| user_id | int |  | false |  |  | [user](user.md) |
| comment_post_id | bigint |  | false |  |  |  |
| comment_user_id | int |  | false |  |  |  |
| created | timestamp |  | false |  |  |  |
| updated | timestamp |  | true |  |  |  |

## Constraints

| Name | Type | Definition |
| ---- | ---- | ---------- |
| PRIMARY | PRIMARY KEY | PRIMARY KEY (id) |
| user_id | UNIQUE | UNIQUE KEY user_id (user_id, comment_post_id, comment_user_id) |

## Indexes

| Name | Definition |
| ---- | ---------- |
| PRIMARY | PRIMARY KEY (id) USING BTREE |
| user_id | UNIQUE KEY user_id (user_id, comment_post_id, comment_user_id) USING BTREE |

## Relations

![er](comment_star.svg)
