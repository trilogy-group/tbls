# testdb

## Description

Sample database document.

## Labels

`sample` `tbls`

## Tables

| # | Name | Columns | Comment | Type | Labels |
| - | ---- | ------- | ------- | ---- | ------ |
| 1 | [CamelizeTable](CamelizeTable.md) | 2 |  | BASE TABLE |  |
| 2 | [comment_stars](comment_stars.md) | 6 |  | BASE TABLE |  |
| 3 | [comments](comments.md) | 7 | Comments<br>Multi-line<br>table<br>comment | BASE TABLE |  |
| 4 | [hyphen-table](hyphen-table.md) | 3 |  | BASE TABLE |  |
| 5 | [logs](logs.md) | 7 | Auditログ | BASE TABLE |  |
| 6 | [post_comments](post_comments.md) | 7 | post and comments View table | VIEW |  |
| 7 | [posts](posts.md) | 7 | Posts table | BASE TABLE | `green` `red` `blue` |
| 8 | [user_options](user_options.md) | 4 | User options table | BASE TABLE |  |
| 9 | [users](users.md) | 6 | Users table | BASE TABLE |  |

## Relations

![er](schema.svg)
