# public.users

## Description

Users table

## Columns

| Name | Type | Default | Nullable | Children | Comment |
| ---- | ---- | ------- | -------- | -------- | ------- |
| id | integer | nextval('users_id_seq'::regclass) | false | [public.user_options](public.user_options.md) [public.posts](public.posts.md) [public.comments](public.comments.md) [public.comment_stars](public.comment_stars.md) [administrator.blogs](administrator.blogs.md) [public.logs](public.logs.md) |  |
| username | varchar(50) |  | false |  |  |
| password | varchar(50) |  | false |  |  |
| email | varchar(355) |  | false |  | ex. user@example.com |
| created | timestamp without time zone |  | false |  |  |
| updated | timestamp without time zone |  | true |  |  |

## Constraints

| Name | Type | Definition |
| ---- | ---- | ---------- |
| users_username_check | CHECK | CHECK ((char_length((username)::text) > 4)) |
| users_pkey | PRIMARY KEY | PRIMARY KEY (id) |
| users_username_key | UNIQUE | UNIQUE (username) |
| users_email_key | UNIQUE | UNIQUE (email) |

## Indexes

| Name | Definition |
| ---- | ---------- |
| users_pkey | CREATE UNIQUE INDEX users_pkey ON public.users USING btree (id) |
| users_username_key | CREATE UNIQUE INDEX users_username_key ON public.users USING btree (username) |
| users_email_key | CREATE UNIQUE INDEX users_email_key ON public.users USING btree (email) |

## Triggers

| Name | Definition | Comment |
| ---- | ---------- | ------- |
| update_users_updated | CREATE TRIGGER update_users_updated AFTER INSERT OR UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION update_updated() | Update updated when users insert or update |

## Relations

![er](public.users.svg)
