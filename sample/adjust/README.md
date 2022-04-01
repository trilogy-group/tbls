# testdb

## Description

Sample PostgreSQL database document.

## Tables

| Name                                                      | Columns | Comment                                    | Type              |
| --------------------------------------------------------- | ------- | ------------------------------------------ | ----------------- |
| [public.users](public.users.md)                           | 6       | Users table                                | BASE TABLE        |
| [public.user_options](public.user_options.md)             | 4       | User options table                         | BASE TABLE        |
| [public.posts](public.posts.md)                           | 8       | Posts table                                | BASE TABLE        |
| [public.comments](public.comments.md)                     | 7       | Comments<br>Multi-line<br>table<br>comment | BASE TABLE        |
| [public.comment_stars](public.comment_stars.md)           | 6       |                                            | BASE TABLE        |
| [public.logs](public.logs.md)                             | 7       | audit log table                            | BASE TABLE        |
| [public.post_comments](public.post_comments.md)           | 7       | post and comments View table               | VIEW              |
| [public.post_comment_stars](public.post_comment_stars.md) | 5       |                                            | MATERIALIZED VIEW |
| [public.CamelizeTable](public.CamelizeTable.md)           | 2       |                                            | BASE TABLE        |
| [public.hyphen-table](public.hyphen-table.md)             | 4       |                                            | BASE TABLE        |
| [administrator.blogs](administrator.blogs.md)             | 6       | admin blogs                                | BASE TABLE        |
| [backup.blogs](backup.blogs.md)                           | 5       |                                            | BASE TABLE        |
| [backup.blog_options](backup.blog_options.md)             | 4       |                                            | BASE TABLE        |
| [time.bar](time.bar.md)                                   | 1       |                                            | BASE TABLE        |
| [time.hyphenated-table](time.hyphenated-table.md)         | 1       |                                            | BASE TABLE        |
| [time.referencing](time.referencing.md)                   | 3       |                                            | BASE TABLE        |

## Stored procedures and functions

| Name                      | ReturnType | Arguments                 | Type      |
| ------------------------- | ---------- | ------------------------- | --------- |
| public.uuid_nil           | uuid       |                           | FUNCTION  |
| public.uuid_ns_dns        | uuid       |                           | FUNCTION  |
| public.uuid_ns_url        | uuid       |                           | FUNCTION  |
| public.uuid_ns_oid        | uuid       |                           | FUNCTION  |
| public.uuid_ns_x500       | uuid       |                           | FUNCTION  |
| public.uuid_generate_v1   | uuid       |                           | FUNCTION  |
| public.uuid_generate_v1mc | uuid       |                           | FUNCTION  |
| public.uuid_generate_v3   | uuid       | namespace uuid, name text | FUNCTION  |
| public.uuid_generate_v4   | uuid       |                           | FUNCTION  |
| public.uuid_generate_v5   | uuid       | namespace uuid, name text | FUNCTION  |
| public.update_updated     | trigger    |                           | FUNCTION  |
| public.reset_comment      | void       | comment_id integer        | PROCEDURE |

## Relations

![er](schema.svg)
