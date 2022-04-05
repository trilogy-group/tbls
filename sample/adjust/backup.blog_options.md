# backup.blog_options

## Description

## Columns

| Name    | Type                        | Default                                  | Nullable | Parents                         |
| ------- | --------------------------- | ---------------------------------------- | -------- | ------------------------------- |
| id      | integer                     | nextval('blog_options_id_seq'::regclass) | false    |                                 |
| blog_id | integer                     |                                          | false    | [backup.blogs](backup.blogs.md) |
| label   | text                        |                                          | true     |                                 |
| updated | timestamp without time zone |                                          | true     |                                 |

## Constraints

| Name                    | Type        | Definition                                                   |
| ----------------------- | ----------- | ------------------------------------------------------------ |
| blog_options_blog_id_fk | FOREIGN KEY | FOREIGN KEY (blog_id) REFERENCES blogs(id) ON DELETE CASCADE |
| blog_options_pkey       | PRIMARY KEY | PRIMARY KEY (id)                                             |

## Indexes

| Name              | Definition                                                                    |
| ----------------- | ----------------------------------------------------------------------------- |
| blog_options_pkey | CREATE UNIQUE INDEX blog_options_pkey ON backup.blog_options USING btree (id) |

## Relations

![er](backup.blog_options.svg)
