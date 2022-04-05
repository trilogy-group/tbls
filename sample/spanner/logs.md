# logs

## Description

## Columns

| Name | Type | Default | Nullable | Parents |
| ---- | ---- | ------- | -------- | ------- |
| log_id | INT64 |  | false |  |
| user_id | INT64 |  | false | [users](users.md) |
| post_id | INT64 |  | true | [posts](posts.md) |
| comment_id | INT64 |  | true |  |
| comment_star_id | INT64 |  | true |  |
| payload | STRING(MAX) |  | true |  |
| created | TIMESTAMP |  | false |  |

## Constraints

| Name | Type | Definition |
| ---- | ---- | ---------- |
| PRIMARY_KEY | PRIMARY_KEY | PRIMARY KEY(log_id) |

## Relations

![er](logs.svg)
