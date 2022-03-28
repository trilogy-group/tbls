package oracle

import (
	"database/sql"
	"fmt"

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

	tableRows, err := p.db.Query(tablesQuery)
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

		relationsRows, err := p.db.Query(queryForRelations, tableOwner, tableName)
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
		constrainsRows, err := p.db.Query(queryForConstraints, tableOwner, tableName)
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

		columns, err := p.getColumns(tableColumnsQuery, tableOwner, tableName)
		if err != nil {
			return errors.WithStack(err)
		}
		table.Columns = columns

		indexRows, err := p.db.Query(queryForIndexes, tableOwner, tableName)
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

		triggerRows, err := p.db.Query(queryForTriggers, tableOwner, tableName)
		if err != nil {
			return errors.WithStack(err)
		}
		defer triggerRows.Close()

		triggers := []*schema.Trigger{}
		for triggerRows.Next() {
			var (
				triggerName string
				triggerDef  string
				//triggerComment sql.NullString
			)
			err = triggerRows.Scan(&triggerName, &triggerDef)
			if err != nil {
				return errors.WithStack(err)
			}
			trigger := &schema.Trigger{
				Name: triggerName,
				Def:  triggerDef,
			}
			triggers = append(triggers, trigger)
		}
		table.Triggers = triggers

		tables = append(tables, table)
	}

	views, err := p.getViews(viewsQuery)
	if err != nil {
		return errors.WithStack(err)
	}
	tables = append(tables, views...)

	materializedViews, err := p.getViews(materializedViewsQuery)
	if err != nil {
		return errors.WithStack(err)
	}
	tables = append(tables, materializedViews...)

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

	subroutines, err := p.getSubroutines()
	if err != nil {
		return err
	}
	s.Subroutines = subroutines

	return nil
}

func (p *Oracle) getSubroutines() ([]*schema.Subroutine, error) {
	subroutines := []*schema.Subroutine{}
	userDefinedFunctions, err := p.db.Query(queryUserDefinedFunctions)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer userDefinedFunctions.Close()

	for userDefinedFunctions.Next() {
		var (
			owner      string
			name       string
			returnType string
			arguments  string
		)
		err := userDefinedFunctions.Scan(&owner, &name, &returnType, &arguments)
		if err != nil {
			return subroutines, errors.WithStack(err)
		}
		subroutine := &schema.Subroutine{
			Name:       fullTableName(owner, name),
			Type:       "USER DEFINED FUNCTION",
			ReturnType: returnType,
			Arguments:  arguments,
		}

		subroutines = append(subroutines, subroutine)
	}

	soredProcedures, err := p.db.Query(queryStoredProcedures)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer soredProcedures.Close()

	for soredProcedures.Next() {
		var (
			owner     string
			name      string
			arguments string
		)
		err := soredProcedures.Scan(&owner, &name, &arguments)
		if err != nil {
			return subroutines, errors.WithStack(err)
		}
		subroutine := &schema.Subroutine{
			Name:      fullTableName(owner, name),
			Type:      "STORED PROCEDURE",
			Arguments: arguments,
		}

		subroutines = append(subroutines, subroutine)
	}
	return subroutines, nil
}

func (p *Oracle) getViews(query string) ([]*schema.Table, error) {
	viewRows, err := p.db.Query(query)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer viewRows.Close()

	tables := []*schema.Table{}
	for viewRows.Next() {
		var (
			viewName       string
			viewType       string
			viewOwner      string
			viewComment    sql.NullString
			viewDefinition sql.NullString
		)
		err := viewRows.Scan(&viewName, &viewType, &viewOwner, &viewComment, &viewDefinition)
		if err != nil {
			return tables, errors.WithStack(err)
		}
		table := &schema.Table{
			Name:    fullTableName(viewOwner, viewName),
			Type:    viewType,
			Comment: viewComment.String,
			Def:     viewDefinition.String,
		}

		columns, err := p.getColumns(viewColumnsQuery, viewOwner, viewName)
		if err != nil {
			return tables, errors.WithStack(err)
		}
		table.Columns = columns

		tables = append(tables, table)
	}
	return tables, nil
}

func (p *Oracle) getColumns(query string, owner string, name string) ([]*schema.Column, error) {
	columnRows, err := p.db.Query(query, owner, name)
	if err != nil {
		return nil, errors.WithStack(err)
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
			return columns, errors.WithStack(err)
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
			return columns, errors.Errorf("unsupported col.nullable value '%s'", isNullable)
		}

		columns = append(columns, column)
	}
	return columns, nil
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

// queries came from https://dataedo.com/kb/query/oracle

var tablesQuery = `SELECT
  ata.TABLE_NAME, atc.TABLE_TYPE, ata.OWNER, atc.COMMENTS 
FROM
  all_tables ata
JOIN all_tab_comments atc ON atc.OWNER = ata.OWNER AND ata.TABLE_NAME = atc.TABLE_NAME 
WHERE ata.OWNER not in ('ANONYMOUS','CTXSYS','DBSNMP','EXFSYS', 'LBACSYS',
'MDSYS', 'MGMT_VIEW','OLAPSYS','OWBSYS','ORDPLUGINS', 'ORDSYS','OUTLN',
'SI_INFORMTN_SCHEMA','SYS','SYSMAN','SYSTEM', 'TSMSYS','WK_TEST',
'WKPROXY','WMSYS','XDB','APEX_040000', 'APEX_PUBLIC_USER','DIP',
'FLOWS_30000','FLOWS_FILES','MDDATA', 'ORACLE_OCM', 'XS$NULL', 'WKSYS',
'SPATIAL_CSW_ADMIN_USR', 'SPATIAL_WFS_ADMIN_USR', 'PUBLIC', 'DVSYS', 'ORDDATA',
'DBSFWUSER', 'OJVMSYS', 'AUDSYS')`

var tableColumnsQuery = `select col.column_name, 
			col.nullable,
			col.data_type, 
			col.DATA_DEFAULT,
			atc.COMMENTS
	from sys.all_tab_columns col
	inner join sys.all_tables t on col.owner = t.owner and col.table_name = t.table_name
	INNER JOIN all_tab_comments atc ON atc.OWNER = col.OWNER AND col.TABLE_NAME = atc.TABLE_NAME 
	where col.owner = :tableOwner and col.table_name = :tableName`

var viewsQuery = `SELECT
  av.view_name, atc.TABLE_TYPE, av.OWNER, atc.COMMENTS, av.text_vc AS description
FROM
  all_views av
JOIN all_tab_comments atc ON atc.OWNER = av.OWNER AND av.view_name = atc.TABLE_NAME 
WHERE av.OWNER not in ('ANONYMOUS','CTXSYS','DBSNMP','EXFSYS', 'LBACSYS',
'MDSYS', 'MGMT_VIEW','OLAPSYS','OWBSYS','ORDPLUGINS', 'ORDSYS','OUTLN',
'SI_INFORMTN_SCHEMA','SYS','SYSMAN','SYSTEM', 'TSMSYS','WK_TEST',
'WKPROXY','WMSYS','XDB','APEX_040000', 'APEX_PUBLIC_USER','DIP',
'FLOWS_30000','FLOWS_FILES','MDDATA', 'ORACLE_OCM', 'XS$NULL', 'WKSYS',
'SPATIAL_CSW_ADMIN_USR', 'SPATIAL_WFS_ADMIN_USR', 'PUBLIC', 'DVSYS', 'ORDDATA',
'DBSFWUSER', 'OJVMSYS', 'AUDSYS')`

var viewColumnsQuery = `select col.column_name, 
			col.nullable,
			col.data_type, 
			col.DATA_DEFAULT,
			atc.COMMENTS
	from sys.all_tab_columns col
	inner join sys.all_views t on col.owner = t.owner and col.table_name = t.view_name
	INNER JOIN all_tab_comments atc ON atc.OWNER = col.OWNER AND col.TABLE_NAME = atc.TABLE_NAME 
	where col.owner = :viewOwner and col.table_name = :viewName`

var materializedViewsQuery = `SELECT
	amv.mview_name, atc.TABLE_TYPE, amv.OWNER, atc.COMMENTS, query as definition
FROM
	all_mviews amv
JOIN all_tab_comments atc ON atc.OWNER = amv.OWNER AND amv.mview_name = atc.TABLE_NAME 
WHERE amv.OWNER not in ('ANONYMOUS','CTXSYS','DBSNMP','EXFSYS', 'LBACSYS',
'MDSYS', 'MGMT_VIEW','OLAPSYS','OWBSYS','ORDPLUGINS', 'ORDSYS','OUTLN',
'SI_INFORMTN_SCHEMA','SYS','SYSMAN','SYSTEM', 'TSMSYS','WK_TEST',
'WKPROXY','WMSYS','XDB','APEX_040000', 'APEX_PUBLIC_USER','DIP',
'FLOWS_30000','FLOWS_FILES','MDDATA', 'ORACLE_OCM', 'XS$NULL', 'WKSYS',
'SPATIAL_CSW_ADMIN_USR', 'SPATIAL_WFS_ADMIN_USR', 'PUBLIC', 'DVSYS', 'ORDDATA',
'DBSFWUSER', 'OJVMSYS', 'AUDSYS')`

var materializedViewColumnsQuery = `select col.column_name, 
			col.nullable,
			col.data_type, 
			col.DATA_DEFAULT,
			atc.COMMENTS
	from sys.all_tab_columns col
	inner join sys.all_mviews t on col.owner = t.owner and col.table_name = t.mview_name
	INNER JOIN all_tab_comments atc ON atc.OWNER = col.OWNER AND col.TABLE_NAME = atc.TABLE_NAME 
	where col.owner = :viewOwner and col.table_name = :viewName`

var queryForRelations = `SELECT distinct c.CONSTRAINT_NAME, c.CONSTRAINT_TYPE, a.column_name child_column, 
	b.table_name parent_table, b.column_name parent_column, b.OWNER as parent_table_owner
FROM all_constraints c
JOIN all_cons_columns a ON a.owner = c.owner AND a.constraint_name = c.constraint_name
join all_cons_columns b on c.owner = b.owner and c.r_constraint_name = b.constraint_name
WHERE c.CONSTRAINT_TYPE = 'R' and a.owner = :tableOwner and a.table_name = :tableName`

var queryForConstraints = `select ctr.constraint_name, 
	ctr.CONSTRAINT_TYPE,
	col.column_name,
	ctr.SEARCH_CONDITION as constraint,
	ctr.status
from sys.all_constraints ctr
join sys.all_cons_columns col on ctr.owner = col.owner and ctr.constraint_name = col.constraint_name and ctr.table_name = col.table_name
WHERE ctr.CONSTRAINT_TYPE = 'C' and ctr.owner = :tableOwner and ctr.table_name = :tableName`

var queryForIndexes = `select ind.index_name,
	ind_col.column_name,
	ind.index_type
from sys.all_indexes ind
inner join sys.all_ind_columns ind_col on ind.owner = ind_col.index_owner
	and ind.index_name = ind_col.index_name
WHERE ind.table_owner = :tableOwner and ind.table_name = :tableName`

var queryForTriggers = `select trig.trigger_name,
	trig.trigger_body as script 
from sys.all_triggers trig
WHERE trig.table_owner = :tableOwner and trig.table_name = :tableName`

var queryUserDefinedFunctions = `select obj.owner, obj.object_name as function_name,
ret.data_type as return_type,
LISTAGG(args.in_out || ' ' || args.data_type, '; ')
			 WITHIN GROUP (ORDER BY position) as arguments
from sys.all_objects obj
join sys.all_arguments args on args.object_id = obj.object_id
join (
select object_id,
			object_name,
			data_type
from sys.all_arguments
where position = 0
) ret on ret.object_id = args.object_id
and ret.object_name = args.object_name
where obj.object_type = 'FUNCTION' and args.position > 0 and obj.owner not in ('ANONYMOUS','CTXSYS','DBSNMP','EXFSYS', 'LBACSYS',
'MDSYS', 'MGMT_VIEW','OLAPSYS','OWBSYS','ORDPLUGINS', 'ORDSYS','OUTLN',
'SI_INFORMTN_SCHEMA','SYS','SYSMAN','SYSTEM', 'TSMSYS','WK_TEST',
'WKPROXY','WMSYS','XDB','APEX_040000', 'APEX_PUBLIC_USER','DIP',
'FLOWS_30000','FLOWS_FILES','MDDATA', 'ORACLE_OCM', 'XS$NULL', 'WKSYS',
'SPATIAL_CSW_ADMIN_USR', 'SPATIAL_WFS_ADMIN_USR', 'PUBLIC', 'DVSYS', 'ORDDATA',
'DBSFWUSER', 'OJVMSYS', 'AUDSYS')
group by obj.owner, obj.object_name, ret.data_type`

var queryStoredProcedures = `select proc.owner, proc.object_name as procedure_name,
	LISTAGG(args.argument_name || ' ' || args.in_out  || 
					 ' ' || args.data_type, '; ')
				 WITHIN GROUP (ORDER BY position) as arguments
from sys.all_procedures proc
left join sys.all_arguments args
on proc.object_id = args.object_id
where object_type = 'PROCEDURE' and proc.owner not in ('ANONYMOUS','CTXSYS','DBSNMP','EXFSYS', 'LBACSYS',
'MDSYS', 'MGMT_VIEW','OLAPSYS','OWBSYS','ORDPLUGINS', 'ORDSYS','OUTLN',
'SI_INFORMTN_SCHEMA','SYS','SYSMAN','SYSTEM', 'TSMSYS','WK_TEST',
'WKPROXY','WMSYS','XDB','APEX_040000', 'APEX_PUBLIC_USER','DIP',
'FLOWS_30000','FLOWS_FILES','MDDATA', 'ORACLE_OCM', 'XS$NULL', 'WKSYS',
'SPATIAL_CSW_ADMIN_USR', 'SPATIAL_WFS_ADMIN_USR', 'PUBLIC', 'DVSYS', 'ORDDATA',
'DBSFWUSER', 'OJVMSYS', 'AUDSYS')
group by proc.owner, proc.object_name`
