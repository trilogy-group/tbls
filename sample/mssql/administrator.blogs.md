# administrator.blogs

## Description

admin blogs

## Columns

| Name | Type | Default | Nullable | Parents |
| ---- | ---- | ------- | -------- | ------- |
| id | int |  | false |  |
| user_id | int |  | false | [users](users.md) | 
| name | text |  | false |  |
| description | text |  | true |  |
| created | date |  | false |  |
| updated | date |  | true |  |

## Constraints

| Name | Type | Definition |
| ---- | ---- | ---------- |
| PK__blogs_* | PRIMARY KEY | CLUSTERED, unique, part of a PRIMARY KEY constraint, [ id ] |
| blogs_user_id_fk | FOREIGN KEY | FOREIGN KEY(user_id) REFERENCES users(id) ON UPDATE NO_ACTION ON DELETE CASCADE |

## Indexes

| Name | Definition |
| ---- | ---------- |
| PK__blogs_* | CLUSTERED, unique, part of a PRIMARY KEY constraint, [ id ] |

## Relations

![er](administrator.blogs.svg)
