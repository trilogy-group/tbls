# user_options

## Description

User options

## Columns

| Name | Type | Default | Nullable | Parents | Comment |
| ---- | ---- | ------- | -------- | ------- | ------- |
| user_id | INT64 |  | false | [users](users.md) |  |
| show_email | BOOL |  | false |  | Show email address |
| created | TIMESTAMP |  | false |  |  |
| updated | TIMESTAMP (allow_commit_timestamp=TRUE) |  | true |  |  |

## Constraints

| Name | Type | Definition |
| ---- | ---- | ---------- |
| PRIMARY_KEY | PRIMARY_KEY | PRIMARY KEY(user_id) |
| INTERLEAVE | INTERLEAVE | INTERLEAVE IN PARENT users ON DELETE CASCADE |

## Relations

![er](user_options.svg)
