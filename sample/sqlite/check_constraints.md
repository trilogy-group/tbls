# check_constraints

## Description

<details>
<summary><strong>Table Definition</strong></summary>

```sql
CREATE TABLE check_constraints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  col TEXT CHECK(length(col) > 4),
  brackets TEXT UNIQUE NOT NULL CHECK(((length(brackets) > 4))),
  checkcheck TEXT UNIQUE NOT NULL CHECK(length(checkcheck) > 4),
  downcase TEXT UNIQUE NOT NULL check(length(downcase) > 4),
  nl TEXT UNIQUE NOT
    NULL check(length(nl) > 4 OR
      nl != 'ln')
)
```

</details>

## Columns

| Name | Type | Default | Nullable | Children | Parents | Comment |
| ---- | ---- | ------- | -------- | -------- | ------- | ------- |
| id | INTEGER |  | true |  |  |  |
| col | TEXT |  | true |  |  |  |
| brackets | TEXT |  | false |  |  |  |
| checkcheck | TEXT |  | false |  |  |  |
| downcase | TEXT |  | false |  |  |  |
| nl | TEXT |  | false |  |  |  |

## Constraints

| Name | Type | Definition |
| ---- | ---- | ---------- |
| id | PRIMARY KEY | PRIMARY KEY (id) |
| sqlite_autoindex_check_constraints_4 | UNIQUE | UNIQUE (nl) |
| sqlite_autoindex_check_constraints_3 | UNIQUE | UNIQUE (downcase) |
| sqlite_autoindex_check_constraints_2 | UNIQUE | UNIQUE (checkcheck) |
| sqlite_autoindex_check_constraints_1 | UNIQUE | UNIQUE (brackets) |
| - | CHECK | CHECK(length(col) > 4) |
| - | CHECK | CHECK(((length(brackets) > 4))) |
| - | CHECK | CHECK(length(checkcheck) > 4) |
| - | CHECK | check(length(downcase) > 4) |
| - | CHECK | check(length(nl) > 4 OR nl != 'ln') |

## Indexes

| Name | Definition |
| ---- | ---------- |
| sqlite_autoindex_check_constraints_4 | UNIQUE (nl) |
| sqlite_autoindex_check_constraints_3 | UNIQUE (downcase) |
| sqlite_autoindex_check_constraints_2 | UNIQUE (checkcheck) |
| sqlite_autoindex_check_constraints_1 | UNIQUE (brackets) |

## Relations

![er](check_constraints.svg)
