# name with spaces

## Description

<details>
<summary><strong>Table Definition</strong></summary>

```sql
CREATE VIEW "name with spaces" AS (
  SELECT TOP 1 p.title
  FROM posts AS p
);
```

</details>

## Referenced Tables

- [posts](posts.md)

## Columns

| Name | Type | Default | Nullable |
| ---- | ---- | ------- | -------- |
| title | varchar(255) |  | false |

## Relations

![er](name%20with%20spaces.svg)
