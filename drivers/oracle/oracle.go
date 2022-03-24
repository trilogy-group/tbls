package oracle

import (
	"database/sql"
	"fmt"

	// "regexp"
	// "strings"

	// "github.com/aquasecurity/go-version/pkg/version"
	"github.com/k1LoW/tbls/schema"
	"github.com/pkg/errors"
	_ "github.com/sijms/go-ora"
)

// Oracle struct
type Oracle struct {
	db *sql.DB
}

type relationLink struct {
	table         string
	columns       []string
	parentTable   string
	parentColumns []string
}

func New(db *sql.DB) *Oracle {
	return &Oracle{
		db: db,
	}
}

func (p *Oracle) Analyze(s *schema.Schema) error {
	d, err := p.Info()
	if err != nil {
		return errors.WithStack(err)
	}
	s.Driver = d

	// current schema
	var currentSchema string
	schemaRows, err := p.db.Query(`select sys_context( 'userenv', 'current_schema' ) from dual`)
	if err != nil {
		return errors.WithStack(err)
	}
	defer schemaRows.Close()
	for schemaRows.Next() {
		err := schemaRows.Scan(&currentSchema)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	// select table_name, constraint_name, search_condition text from all_constraints where constraint_type = 'C' and constraint_name not like 'SYS%'
	tableRows, err := p.db.Query(tablesQuery())
	if err != nil {
		return errors.WithStack(err)
	}
	defer tableRows.Close()

	tables := []*schema.Table{}
	links := []relationLink{}

	for tableRows.Next() {
		var (
			tableName    string
			tableType    string
			tableOwner   string
			tableComment sql.NullString
		)
		err := tableRows.Scan(&tableName, &tableType, &tableOwner, &tableComment)
		if err != nil {
			return errors.WithStack(err)
		}
		table := &schema.Table{
			Name:    fullTableName(tableOwner, tableName),
			Type:    tableType,
			Comment: tableComment.String,
		}

		constraints := []*schema.Constraint{}

		relationsRows, err := p.db.Query(queryForRelations(), tableOwner, tableName)
		if err != nil {
			return errors.WithStack(err)
		}
		defer relationsRows.Close()

		for relationsRows.Next() {
			var (
				constraintName                 string
				constraintType                 string
				constraintReferencedTable      sql.NullString
				constraintColumnName           sql.NullString
				constraintReferencedColumnName sql.NullString
				constraintReferencedTableOwner sql.NullString
				//constraintComment               sql.NullString
			)
			err = relationsRows.Scan(&constraintName, &constraintType, &constraintColumnName,
				&constraintReferencedTable, &constraintReferencedColumnName, &constraintReferencedTableOwner)
			if err != nil {
				return errors.WithStack(err)
			}
			rt := fullTableName(constraintReferencedTableOwner.String, constraintReferencedTable.String)
			constraint := &schema.Constraint{
				Name:              constraintName,
				Type:              constraintTypeFullName(constraintType),
				Table:             &table.Name,
				Columns:           []string{constraintColumnName.String},
				ReferencedTable:   &rt,
				ReferencedColumns: []string{constraintReferencedColumnName.String},
				//Comment:           constraintComment.String,
			}
			if constraintType == "R" {
				links = append(links, relationLink{
					table:         table.Name,
					columns:       []string{constraintColumnName.String},
					parentTable:   rt,
					parentColumns: []string{constraintReferencedColumnName.String},
				})
			}
			constraints = append(constraints, constraint)
		}
		constrainsRows, err := p.db.Query(queryForConstraints(), tableOwner, tableName)
		if err != nil {
			return errors.WithStack(err)
		}
		defer constrainsRows.Close()
		for constrainsRows.Next() {
			var (
				constraintName       string
				constraintType       string
				constraintColumnName sql.NullString
				constraintDef        sql.NullString
				constraintStatus     sql.NullString
			)
			err = constrainsRows.Scan(&constraintName, &constraintType, &constraintColumnName, &constraintDef, &constraintStatus)
			if err != nil {
				return errors.WithStack(err)
			}
			constraint := &schema.Constraint{
				Name:    constraintName,
				Type:    constraintTypeFullName(constraintType),
				Table:   &table.Name,
				Columns: []string{constraintColumnName.String},
				Def:     constraintDef.String,
				Comment: constraintStatus.String,
			}
			constraints = append(constraints, constraint)
		}
		table.Constraints = constraints

		columnRows, err := p.db.Query(columnsQuery(), tableOwner, tableName)
		if err != nil {
			return errors.WithStack(err)
		}
		defer columnRows.Close()
		columns := []*schema.Column{}
		for columnRows.Next() {
			var (
				columnName    string
				isNullable    string
				dataType      string
				dataDefault   sql.NullString
				columnComment sql.NullString
			)
			err = columnRows.Scan(&columnName, &isNullable, &dataType, &dataDefault, &columnComment)
			if err != nil {
				return errors.WithStack(err)
			}
			column := &schema.Column{
				Name:    columnName,
				Type:    dataType,
				Default: dataDefault,
				Comment: columnComment.String,
			}
			switch isNullable {
			case "N":
				column.Nullable = false
			case "Y":
				column.Nullable = true
			default:
				return errors.Errorf("unsupported col.nullable value '%s'", isNullable)
			}

			columns = append(columns, column)
		}
		table.Columns = columns

		indexRows, err := p.db.Query(queryForIndexes(), tableOwner, tableName)
		if err != nil {
			return errors.WithStack(err)
		}
		defer indexRows.Close()

		indexes := []*schema.Index{}
		for indexRows.Next() {
			var (
				indexName       string
				indexDef        string
				indexColumnName sql.NullString
				indexComment    sql.NullString
			)
			err = indexRows.Scan(&indexName, &indexColumnName, &indexComment)
			if err != nil {
				return errors.WithStack(err)
			}
			index := &schema.Index{
				Name:    indexName,
				Def:     indexDef,
				Table:   &table.Name,
				Columns: []string{indexColumnName.String},
				Comment: indexComment.String,
			}

			indexes = append(indexes, index)
		}
		table.Indexes = indexes

		tables = append(tables, table)
	}

	s.Tables = tables
	relations := []*schema.Relation{}
	for _, l := range links {
		r := &schema.Relation{}
		table, err := s.FindTableByName(l.table)
		if err != nil {
			return err
		}
		r.Table = table
		for _, c := range l.columns {
			column, err := table.FindColumnByName(c)
			if err != nil {
				return err
			}
			r.Columns = append(r.Columns, column)
			column.ParentRelations = append(column.ParentRelations, r)
		}
		parentTable, err := s.FindTableByName(l.parentTable)
		if err != nil {
			return err
		}
		r.ParentTable = parentTable
		for _, c := range l.parentColumns {
			column, err := parentTable.FindColumnByName(c)
			if err != nil {
				return err
			}
			r.ParentColumns = append(r.ParentColumns, column)
			column.ChildRelations = append(column.ChildRelations, r)
		}
		relations = append(relations, r)
	}
	s.Relations = relations

	return nil
}

func constraintTypeFullName(constraintType string) string {
	switch constraintType {
	case "R":
		return "Referential integrity"
	case "C":
		return "Check constraint on a table"
	default:
		return constraintType
	}
}

func fullTableName(owner string, tableName string) string {
	return fmt.Sprintf("%s.%s", owner, tableName)
}

func (p *Oracle) Info() (*schema.Driver, error) {
	var v string
	row := p.db.QueryRow(`SELECT BANNER FROM v$version`)
	err := row.Scan(&v)
	if err != nil {
		return nil, err
	}

	name := "oracle"

	d := &schema.Driver{
		Name:            name,
		DatabaseVersion: v,
		Meta:            &schema.DriverMeta{},
	}
	return d, nil
}

var filteredOwners = `not in ('ANONYMOUS','CTXSYS','DBSNMP','EXFSYS', 'LBACSYS',
'MDSYS', 'MGMT_VIEW','OLAPSYS','OWBSYS','ORDPLUGINS', 'ORDSYS','OUTLN',
'SI_INFORMTN_SCHEMA','SYS','SYSMAN','SYSTEM', 'TSMSYS','WK_TEST',
'WKPROXY','WMSYS','XDB','APEX_040000', 'APEX_PUBLIC_USER','DIP',
'FLOWS_30000','FLOWS_FILES','MDDATA', 'ORACLE_OCM', 'XS$NULL', 'WKSYS',
'SPATIAL_CSW_ADMIN_USR', 'SPATIAL_WFS_ADMIN_USR', 'PUBLIC', 'DVSYS', 'ORDDATA',
'DBSFWUSER', 'OJVMSYS', 'AUDSYS')`

func tablesQuery() string {
	return fmt.Sprintf(`SELECT
  ata.TABLE_NAME, atc.TABLE_TYPE, ata.OWNER, atc.COMMENTS 
FROM
  all_tables ata
JOIN all_tab_comments atc ON atc.OWNER = ata.OWNER AND ata.TABLE_NAME = atc.TABLE_NAME 
WHERE ata.OWNER %s`, filteredOwners)
}

func columnsQuery() string {
	return `select col.column_name, 
			col.nullable,
			col.data_type, 
			col.DATA_DEFAULT,
			atc.COMMENTS
	from sys.all_tab_columns col
	inner join sys.all_tables t on col.owner = t.owner and col.table_name = t.table_name
	INNER JOIN all_tab_comments atc ON atc.OWNER = col.OWNER AND col.TABLE_NAME = atc.TABLE_NAME 
	where col.owner = :tableOwner and col.table_name = :tableName`
}

func queryForRelations() string {
	return `SELECT distinct c.CONSTRAINT_NAME, c.CONSTRAINT_TYPE, a.column_name child_column, 
	b.table_name parent_table, b.column_name parent_column, b.OWNER as parent_table_owner
FROM all_constraints c
JOIN all_cons_columns a ON a.owner = c.owner AND a.constraint_name = c.constraint_name
join all_cons_columns b on c.owner = b.owner and c.r_constraint_name = b.constraint_name
WHERE c.CONSTRAINT_TYPE = 'R' and a.owner = :tableOwner and a.table_name = :tableName`
}

func queryForConstraints() string {
	return `select ctr.constraint_name, 
	ctr.CONSTRAINT_TYPE,
	col.column_name,
	ctr.SEARCH_CONDITION as constraint,
	ctr.status
from sys.all_constraints ctr
join sys.all_cons_columns col on ctr.owner = col.owner and ctr.constraint_name = col.constraint_name and ctr.table_name = col.table_name
WHERE ctr.CONSTRAINT_TYPE = 'C' and ctr.owner = :tableOwner and ctr.table_name = :tableName`
}

func queryForIndexes() string {
	return `select ind.index_name,
	ind_col.column_name,
	ind.index_type
from sys.all_indexes ind
inner join sys.all_ind_columns ind_col on ind.owner = ind_col.index_owner
	and ind.index_name = ind_col.index_name
WHERE ind.table_owner = :tableOwner and ind.table_name = :tableName`
}
