# public.CamelizeTable

## Description

## Columns

| Name | Type | Default | Nullable | Children | Parents | Comment |
| ---- | ---- | ------- | -------- | -------- | ------- | ------- |
| id | uuid | uuid_generate_v4() | false | [public.hyphen-table](public.hyphen-table.md) |  |  |
| created | timestamp without time zone |  | false |  |  |  |

## Constraints

| Name | Type | Definition |
| ---- | ---- | ---------- |
| CamelizeTable_id_key | UNIQUE | UNIQUE (id) |

## Indexes

| Name | Definition |
| ---- | ---------- |
| CamelizeTable_id_key | CREATE UNIQUE INDEX "CamelizeTable_id_key" ON public."CamelizeTable" USING btree (id) |

## Relations

![er](public.CamelizeTable.svg)
