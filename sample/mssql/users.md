# users

## Description

Users table

## Columns

| Name | Type | Default | Nullable | Children | Parents | Comment |
| ---- | ---- | ------- | -------- | -------- | ------- | ------- |
| id | int |  | false | [user_options](user_options.md) [posts](posts.md) [comments](comments.md) [comment_stars](comment_stars.md) [administrator.blogs](administrator.blogs.md) [logs](logs.md) |  |  |
| username | varchar(50) |  | false |  |  |  |
| password | varchar(50) |  | false |  |  | long long long long long long long long long long long long long long long long long long long long long description |
| email | varchar(355) |  | false |  |  | ex. user@example.com |
| created | date |  | false |  |  |  |
| updated | date |  | true |  |  |  |

## Constraints

| Name | Type | Definition |
| ---- | ---- | ---------- |
| PK__users_* | PRIMARY KEY | CLUSTERED, unique, part of a PRIMARY KEY constraint, [ id ] |
| UQ__users_* | UNIQUE | NONCLUSTERED, unique, part of a UNIQUE constraint, [ email ] |
| UQ__users_* | UNIQUE | NONCLUSTERED, unique, part of a UNIQUE constraint, [ username ] |
| CK__users__username_* | CHECK | CHECK(len([username])>(4)) |

## Indexes

| Name | Definition |
| ---- | ---------- |
| PK__users_* | CLUSTERED, unique, part of a PRIMARY KEY constraint, [ id ] |
| UQ__users_* | NONCLUSTERED, unique, part of a UNIQUE constraint, [ email ] |
| UQ__users_* | NONCLUSTERED, unique, part of a UNIQUE constraint, [ username ] |

## Triggers

| Name | Definition |
| ---- | ---------- |
| update_users_updated | CREATE TRIGGER update_users_updated<br>ON users<br>AFTER UPDATE<br>AS<br>BEGIN<br>  UPDATE users SET updated = GETDATE()<br>  WHERE id = ( SELECT id FROM deleted)<br>END; |

## Relations

![er](users.svg)
