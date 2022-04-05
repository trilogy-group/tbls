# post_comments

## Description

post and comments View table

<details>
<summary><strong>Table Definition</strong></summary>

```sql
CREATE VIEW post_comments AS (
  SELECT c.id, p.title, u2.username AS post_user, c.comment, u2.username AS comment_user, c.created, c.updated
  FROM posts AS p
  LEFT JOIN comments AS c on p.id = c.post_id
  LEFT JOIN users AS u on u.id = p.user_id
  LEFT JOIN users AS u2 on u2.id = c.user_id
);
```

</details>

## Referenced Tables

- [posts](posts.md)
- [comments](comments.md)
- [users](users.md)

## Columns

| Name | Type | Default | Nullable | Comment |
| ---- | ---- | ------- | -------- | ------- |
| id | int |  | true | comments.id |
| title | varchar(255) |  | false | posts.title |
| post_user | varchar(50) |  | true | posts.users.username |
| comment | text |  | true |  |
| comment_user | varchar(50) |  | true | comments.users.username |
| created | date |  | true | comments.created |
| updated | date |  | true | comments.updated |

## Relations

![er](post_comments.svg)
