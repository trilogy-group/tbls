# user_options

## Description

<details>
<summary><strong>Table Definition</strong></summary>

```sql
CREATE TABLE user_options (
  user_id INTEGER PRIMARY KEY,
  show_email INTEGER NOT NULL DEFAULT 0,
  created NUMERIC NOT NULL,
  updated NUMERIC,
  CONSTRAINT user_options_user_id_fk FOREIGN KEY(user_id) REFERENCES users(id) MATCH NONE ON UPDATE NO ACTION ON DELETE CASCADE
)
```

</details>

## Columns

| Name | Type | Default | Nullable | Children | Parents |
| ---- | ---- | ------- | -------- | -------- | ------- |
| user_id | INTEGER |  | true |  | [users](users.md) |
| show_email | INTEGER | 0 | false |  |  |
| created | NUMERIC |  | false |  |  |
| updated | NUMERIC |  | true |  |  |

## Constraints

| Name | Type | Definition |
| ---- | ---- | ---------- |
| user_id | PRIMARY KEY | PRIMARY KEY (user_id) |
| - (Foreign key ID: 0) | FOREIGN KEY | FOREIGN KEY (user_id) REFERENCES users (id) ON UPDATE NO ACTION ON DELETE CASCADE MATCH NONE |

## Relations

![er](user_options.svg)
