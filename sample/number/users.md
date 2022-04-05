# users

## Description

Users table

<details>
<summary><strong>Table Definition</strong></summary>

```sql
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password` varchar(50) NOT NULL,
  `email` varchar(355) NOT NULL COMMENT 'ex. user@example.com',
  `created` timestamp NOT NULL,
  `updated` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=[Redacted by tbls] DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='Users table'
```

</details>

## Columns

| # | Name | Type | Default | Nullable | Extra Definition | Children | Comment |
| - | ---- | ---- | ------- | -------- | ---------------- | -------- | ------- |
| 1 | id | int |  | false | auto_increment | [comment_stars](comment_stars.md) [comments](comments.md) [posts](posts.md) [user_options](user_options.md) |  |
| 2 | username | varchar(50) |  | false |  |  |  |
| 3 | password | varchar(50) |  | false |  |  |  |
| 4 | email | varchar(355) |  | false |  |  | ex. user@example.com |
| 5 | created | timestamp |  | false |  |  |  |
| 6 | updated | timestamp |  | true |  |  |  |

## Constraints

| # | Name | Type | Definition |
| - | ---- | ---- | ---------- |
| 1 | email | UNIQUE | UNIQUE KEY email (email) |
| 2 | PRIMARY | PRIMARY KEY | PRIMARY KEY (id) |
| 3 | username | UNIQUE | UNIQUE KEY username (username) |

## Indexes

| # | Name | Definition |
| - | ---- | ---------- |
| 1 | PRIMARY | PRIMARY KEY (id) USING BTREE |
| 2 | email | UNIQUE KEY email (email) USING BTREE |
| 3 | username | UNIQUE KEY username (username) USING BTREE |

## Relations

![er](users.svg)
