# testdb

## Description

Sample database document.

## Labels

`sample` `tbls`

## Tables

| Name | Columns | Comment | Type | Labels |
| ---- | ------- | ------- | ---- | ------ |
| [users](users.md) | 6 | Users table | BASIC TABLE |  |
| [user_options](user_options.md) | 4 | User options table | BASIC TABLE |  |
| [posts](posts.md) | 6 |  | BASIC TABLE | `green` `red` `blue` |
| [comments](comments.md) | 6 |  | BASIC TABLE |  |
| [comment_stars](comment_stars.md) | 6 |  | BASIC TABLE |  |
| [logs](logs.md) | 7 |  | BASIC TABLE |  |
| [post_comments](post_comments.md) | 7 | post and comments View table | VIEW |  |
| [CamelizeTable](CamelizeTable.md) | 2 |  | BASIC TABLE |  |
| [hyphen-table](hyphen-table.md) | 3 |  | BASIC TABLE |  |
| [administrator.blogs](administrator.blogs.md) | 6 | admin blogs | BASIC TABLE |  |

## Subroutines

| Name | ReturnType | Arguments | Type |
| ---- | ------- | ------- | ---- |
| dbo.get_user |  | @userid int | SQL inline table-valued function |
| dbo.What_DB_is_that |  | @ID int | SQL Stored Procedure |

## Relations

![er](schema.svg)
