# comment_stars

## Description

## Columns

| Name | Type | Default | Nullable | Children | Parents | Comment |
| ---- | ---- | ------- | -------- | -------- | ------- | ------- |
| id | int |  | false | [logs](logs.md) |  |  |
| user_id | int |  | false |  |  |  |
| comment_post_id | int |  | false |  | [comments](comments.md) |  |
| comment_user_id | int |  | false |  | [users](users.md) [comments](comments.md) |  |
| created | date |  | false |  |  |  |
| updated | date |  | true |  |  |  |

## Constraints

| Name | Type | Definition |
| ---- | ---- | ---------- |
| UQ__comment__* | UNIQUE | NONCLUSTERED, unique, part of a UNIQUE constraint, [ user_id, comment_post_id, comment_user_id ] |
| comment_stars_user_id_fk | FOREIGN KEY | FOREIGN KEY(comment_user_id) REFERENCES users(id) ON UPDATE NO_ACTION ON DELETE NO_ACTION |
| comment_stars_user_id_post_id_fk | FOREIGN KEY | FOREIGN KEY(comment_post_id, comment_user_id) REFERENCES comments(post_id, user_id) ON UPDATE NO_ACTION ON DELETE NO_ACTION |

## Indexes

| Name | Definition |
| ---- | ---------- |
| UQ__comment__* | NONCLUSTERED, unique, part of a UNIQUE constraint, [ user_id, comment_post_id, comment_user_id ] |

## Relations

![er](comment_stars.svg)
