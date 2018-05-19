# comments

## Columns

| Name | Type | Default | NOT NULL | Comment |
| ---- | ---- | ------- | -------- | ------- |
| id | bigint | nextval('comments_id_seq'::regclass) | true |  |
| post_id | integer |  | true |  |
| user_id | integer |  | true |  |
| comment | text |  | true |  |
| created | timestamp without time zone |  | true |  |
| updated | timestamp without time zone |  | false |  |