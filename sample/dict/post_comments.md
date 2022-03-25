# post_comments

## 概要

VIEW

<details>
<summary><strong>テーブル定義</strong></summary>

```sql
CREATE VIEW post_comments AS (select `c`.`id` AS `id`,`p`.`title` AS `title`,`u2`.`username` AS `post_user`,`c`.`comment` AS `comment`,`u2`.`username` AS `comment_user`,`c`.`created` AS `created`,`c`.`updated` AS `updated` from (((`testdb`.`posts` `p` left join `testdb`.`comments` `c` on((`p`.`id` = `c`.`post_id`))) left join `testdb`.`users` `u` on((`u`.`id` = `p`.`user_id`))) left join `testdb`.`users` `u2` on((`u2`.`id` = `c`.`user_id`))))
```

</details>

## Referenced Tables

- [posts](posts.md)
- [comments](comments.md)
- [users](users.md)

## カラム一覧

| 名前           | タイプ          | デフォルト値       | Nullable | 子テーブル      | 親テーブル      | コメント                                       |
| ------------ | ------------ | ------------ | -------- | ---------- | ---------- | ------------------------------------------ |
| id           | bigint       | 0            | true     |            |            |                                            |
| title        | varchar(255) | Untitled     | false    |            |            |                                            |
| post_user    | varchar(50)  |              | true     |            |            |                                            |
| comment      | text         |              | true     |            |            | Comment<br>Multi-line<br>column<br>comment |
| comment_user | varchar(50)  |              | true     |            |            |                                            |
| created      | datetime     |              | true     |            |            |                                            |
| updated      | datetime     |              | true     |            |            |                                            |

## ER図

![er](post_comments.svg)
