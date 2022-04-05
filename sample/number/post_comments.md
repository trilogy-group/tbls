# post_comments

## Description

post and comments View table

<details>
<summary><strong>Table Definition</strong></summary>

```sql
CREATE VIEW post_comments AS (select `c`.`id` AS `id`,`p`.`title` AS `title`,`u2`.`username` AS `post_user`,`c`.`comment` AS `comment`,`u2`.`username` AS `comment_user`,`c`.`created` AS `created`,`c`.`updated` AS `updated` from (((`testdb`.`posts` `p` left join `testdb`.`comments` `c` on((`p`.`id` = `c`.`post_id`))) left join `testdb`.`users` `u` on((`u`.`id` = `p`.`user_id`))) left join `testdb`.`users` `u2` on((`u2`.`id` = `c`.`user_id`))))
```

</details>

## Referenced Tables

- [posts](posts.md)
- [comments](comments.md)
- [users](users.md)

## Columns

| # | Name | Type | Default | Nullable | Comment |
| - | ---- | ---- | ------- | -------- | ------- |
| 1 | id | bigint | 0 | true | comments.id |
| 2 | title | varchar(255) | Untitled | false | posts.title |
| 3 | post_user | varchar(50) |  | true | posts.users.username |
| 4 | comment | text |  | true | Comment<br>Multi-line<br>column<br>comment |
| 5 | comment_user | varchar(50) |  | true | comments.users.username |
| 6 | created | datetime |  | true | comments.created |
| 7 | updated | datetime |  | true | comments.updated |

## Relations

![er](post_comments.svg)
