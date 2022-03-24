package oracle

import (
	"database/sql"
	"fmt"
	// "regexp"
	// "strings"

	// "github.com/aquasecurity/go-version/pkg/version"
	"github.com/k1LoW/tbls/schema"
	_ "github.com/sijms/go-ora"
	"github.com/pkg/errors"
)

// Oracle struct
type Oracle struct {
	db        *sql.DB
}

type relationLink struct {
	table         string
	columns       []string
	parentTable   string
	parentColumns []string
}

func New(db *sql.DB) *Oracle {
	return &Oracle{
		db:     db,
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
			tableSchema  string
			tableComment sql.NullString
		)
		err := tableRows.Scan(&tableName, &tableType, &tableSchema, &tableComment)
		if err != nil {
			return errors.WithStack(err)
		}
		table := &schema.Table{
			Name:    tableName,
			Type:    tableType,
			Comment: tableComment.String,
		}

		constraintRows, err := p.db.Query(queryForConstraints(), tableName)
		if err != nil {
			return errors.WithStack(err)
		}
		defer constraintRows.Close()

		constraints := []*schema.Constraint{}
		for constraintRows.Next() {
			var (
				constraintName                  string
				constraintType                  string
				constraintReferencedTable       sql.NullString
				constraintColumnName           sql.NullString
				constraintReferencedColumnName sql.NullString
				//constraintComment               sql.NullString
			)
			err = constraintRows.Scan(&constraintName, &constraintType, &constraintColumnName, &constraintReferencedTable, &constraintReferencedColumnName)
			if err != nil {
				return errors.WithStack(err)
			}
			rt := constraintReferencedTable.String
			constraint := &schema.Constraint{
				Name:              constraintName,
				Type:              constraintType,
				Table:             &table.Name,
				Columns:           []string{constraintColumnName.String},
				ReferencedTable:   &rt,
				ReferencedColumns: []string{constraintReferencedColumnName.String},
				//Comment:           constraintComment.String,
			}

			links = append(links, relationLink{
				table:         table.Name,
				columns:       []string{constraintColumnName.String},
				parentTable:   constraintReferencedTable.String,
				parentColumns: []string{constraintReferencedColumnName.String},
			})
			constraints = append(constraints, constraint)
		}
		table.Constraints = constraints

// select col.column_id, 
// 		col.owner as schema_name,
// 		col.table_name, 
// 		col.column_name, 
// 		col.data_type, 
// 		col.data_length, 
// 		col.data_precision, 
// 		col.data_scale, 
// 		col.nullable
// from sys.all_tab_columns col
// inner join sys.all_tables t on col.owner = t.owner and col.table_name = t.table_name
// where col.owner = 'OT' and col.table_name = $1::tableName

		columnRows, err := p.db.Query(columnsQuery(), tableName)
		if err != nil {
			return errors.WithStack(err)
		}
		defer columnRows.Close()
		columns := []*schema.Column{}
		for columnRows.Next() {
			var (
				columnName               string
				isNullable               string
				dataType                 string
				columnComment            sql.NullString
			)
			err = columnRows.Scan(&columnName, &isNullable, &dataType, &columnComment)
			if err != nil {
				return errors.WithStack(err)
			}
			column := &schema.Column{
				Name:     columnName,
				Type:     dataType,
				Comment:  columnComment.String,
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

func filteredOwners() string {
	return `not in ('ANONYMOUS','CTXSYS','DBSNMP','EXFSYS', 'LBACSYS',
'MDSYS', 'MGMT_VIEW','OLAPSYS','OWBSYS','ORDPLUGINS', 'ORDSYS','OUTLN',
'SI_INFORMTN_SCHEMA','SYS','SYSMAN','SYSTEM', 'TSMSYS','WK_TEST',
'WKPROXY','WMSYS','XDB','APEX_040000', 'APEX_PUBLIC_USER','DIP',
'FLOWS_30000','FLOWS_FILES','MDDATA', 'ORACLE_OCM', 'XS$NULL', 'WKSYS',
'SPATIAL_CSW_ADMIN_USR', 'SPATIAL_WFS_ADMIN_USR', 'PUBLIC', 'DVSYS', 'ORDDATA',
'DBSFWUSER', 'OJVMSYS', 'AUDSYS')`
}

func tablesQuery() string {
	return fmt.Sprintf(`SELECT
  ata.TABLE_NAME, atc.TABLE_TYPE, ata.OWNER, atc.COMMENTS 
FROM
  all_tables ata
JOIN all_tab_comments atc ON atc.OWNER = ata.OWNER AND ata.TABLE_NAME = atc.TABLE_NAME 
WHERE ata.OWNER %s`, filteredOwners())
}

func columnsQuery() string {
	return fmt.Sprintf(`select col.column_name, 
			col.nullable,
			col.data_type, 
			atc.COMMENTS
	from sys.all_tab_columns col
	inner join sys.all_tables t on col.owner = t.owner and col.table_name = t.table_name
	INNER JOIN all_tab_comments atc ON atc.OWNER = col.OWNER AND col.TABLE_NAME = atc.TABLE_NAME 
	where col.owner %s and col.table_name = :tableName`, filteredOwners())
}

func queryForConstraints() string {
	return fmt.Sprintf(`SELECT c.CONSTRAINT_NAME, c.CONSTRAINT_TYPE , a.column_name child_column, 
	b.table_name parent_table, b.column_name parent_column
FROM all_cons_columns a
JOIN all_constraints c ON a.owner = c.owner AND a.constraint_name = c.constraint_name
join all_cons_columns b on c.owner = b.owner and c.r_constraint_name = b.constraint_name
WHERE c.constraint_type = 'R' and a.table_name = :tableName and a.owner %s`, filteredOwners())
}
