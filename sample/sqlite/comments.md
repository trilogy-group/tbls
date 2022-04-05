# comments

## Description

<details>
<summary><strong>Table Definition</strong></summary>

```sql
CREATE TABLE comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  comment TEXT NOT NULL,
  created NUMERIC NOT NULL,
  updated NUMERIC,
  CONSTRAINT comments_post_id_fk FOREIGN KEY(post_id) REFERENCES posts(id),
  CONSTRAINT comments_user_id_fk FOREIGN KEY(user_id) REFERENCES users(id),
  UNIQUE(post_id, user_id)
)
```

</details>

## Columns

| Name | Type | Default | Nullable | Children | Parents |
| ---- | ---- | ------- | -------- | -------- | ------- |
| id | INTEGER |  | true | [logs](logs.md) |  |
| post_id | INTEGER |  | false | [comment_stars](comment_stars.md) | [posts](posts.md) |
| user_id | INTEGER |  | false | [comment_stars](comment_stars.md) | [users](users.md) |
| comment | TEXT |  | false |  |  |
| created | NUMERIC |  | false |  |  |
| updated | NUMERIC |  | true |  |  |

## Constraints

| Name | Type | Definition |
| ---- | ---- | ---------- |
| id | PRIMARY KEY | PRIMARY KEY (id) |
| - (Foreign key ID: 0) | FOREIGN KEY | FOREIGN KEY (user_id) REFERENCES users (id) ON UPDATE NO ACTION ON DELETE NO ACTION MATCH NONE |
| - (Foreign key ID: 1) | FOREIGN KEY | FOREIGN KEY (post_id) REFERENCES posts (id) ON UPDATE NO ACTION ON DELETE NO ACTION MATCH NONE |
| sqlite_autoindex_comments_1 | UNIQUE | UNIQUE (post_id, user_id) |

## Indexes

| Name | Definition |
| ---- | ---------- |
| comments_post_id_user_id_idx | CREATE INDEX comments_post_id_user_id_idx ON comments(post_id, user_id) |
| sqlite_autoindex_comments_1 | UNIQUE (post_id, user_id) |

## Relations

![er](comments.svg)
