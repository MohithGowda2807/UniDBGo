> **Note:** this is the original planning document written before implementation. The implemented design is described in the README; where the two differ (for example, Redis support and the `Connect(connStr)` driver signature planned here), the code and README are authoritative.

**1\. Foundation & Architecture Design (UniDB-Go)**

This phase is the **most critical**—it defines how scalable, extensible, and “intelligent” your system will be. Think of this as building the _blueprint of a database engine + middleware hybrid_.

**1.1 Define System Goals (Clear Engineering Targets)**

Before writing code, lock in **non-negotiable goals**:

**Functional Goals**

*   Unified interface for:
    *   SQL (PostgreSQL, MySQL)
    *   NoSQL (MongoDB, Redis)
*   Cross-database querying (federation)
*   Intelligent query routing
*   Built-in security layer
*   Plug-and-play driver system

**Non-Functional Goals**

*   Low latency (<10–20% overhead vs native drivers)
*   High concurrency (goroutine-safe)
*   Extensibility (new DB drivers easily added)
*   Observability (logs, metrics)

**1.2 Define High-Level Architecture**

Design the system as a **modular pipeline**:

Application  
↓  
API Layer  
↓  
Query Parser  
↓  
Query Planner  
↓  
Security Engine  
↓  
Query Router  
↓  
Execution Engine  
↓  
Connection Pool Manager  
↓  
Database Drivers

**Key Principle:**

👉 Each module should be **independent and replaceable**

**1.3 Choose Design Patterns**

Use strong software engineering patterns:

**1\. Adapter Pattern (CRITICAL)**

Wrap different DB drivers into a common interface.

type Driver interface {  
Connect(connStr string) error  
Query(query string, args ...interface{}) (Result, error)  
Exec(query string, args ...interface{}) error  
}

**2\. Factory Pattern**

Select driver dynamically.

func NewDriver(dbType string) Driver {  
switch dbType {  
case "postgres":  
return &PostgresDriver{}  
case "mysql":  
return &MySQLDriver{}  
}  
}

**3\. Strategy Pattern**

Used for:

*   Query routing
*   Query optimization

**4\. Pipeline Pattern**

Each stage processes query step-by-step:

*   Parse → Plan → Secure → Route → Execute

**5\. Observer Pattern (for monitoring)**

Used for:

*   logging
*   metrics (Prometheus)

**1.4 Define Core Modules (Deep Design)**

**1\. API Layer**

**Responsibilities:**

*   User-facing interface
*   Query execution
*   Transactions

**Example:**

type DB struct {  
router Router  
}  
  
func (db \*DB) Query(q string, args ...interface{}) (Result, error)

**Design Decisions:**

*   Keep it minimal
*   No DB-specific logic here

**2\. Query Parser**

**Responsibilities:**

*   Convert query → AST (Abstract Syntax Tree)

**Use:**

*   Vitess SQL parser (recommended)

**Output Example:**

SELECT name FROM users

Becomes:

QueryNode  
├── SELECT  
├── FROM users

**Why Important:**

*   Enables query splitting
*   Enables optimization

**3\. Query Planner**

**Responsibilities:**

*   Decide:
    *   execution order
    *   join strategy
    *   database selection

**Inputs:**

*   AST
*   metadata (which DB has which table)

**Output:**

Execution Plan:

Step 1 → Query Postgres.users  
Step 2 → Query MySQL.orders  
Step 3 → Join results

**4\. Security Engine**

**Responsibilities:**

*   Detect malicious queries

**Techniques:**

*   Pattern matching (basic phase)
*   Heuristics (intermediate)
*   ML (advanced)

**Example:**

SELECT \* FROM users WHERE id = 1 OR 1=1

→ flagged as injection

**5\. Query Router**

**Responsibilities:**

*   Route queries to correct DB

**Inputs:**

*   Query Plan
*   Runtime metrics:
    *   latency
    *   load

**Output:**

Route to Postgres (primary)

**6\. Execution Engine**

**Responsibilities:**

*   Execute planned queries
*   Merge results

**Special Case:**

Cross-DB JOIN:

*   execute separately
*   merge in memory

**7\. Connection Pool Manager**

**Responsibilities:**

*   Manage connections efficiently
*   Handle concurrency

**Features:**

*   Dynamic pool sizing
*   Timeout handling
*   Load balancing

**8\. Driver Layer**

**Responsibilities:**

*   DB-specific implementations

**Structure:**

drivers/  
postgres/  
mysql/  
mongodb/  
redis/

**1.5 Define Data Flow (Very Important)**

Example query:

SELECT users.name, orders.total  
FROM postgres.users  
JOIN mysql.orders  
ON users.id = orders.user\_id

**Flow:**

1.  API receives query
2.  Parser → AST
3.  Planner → split query
4.  Security check
5.  Router → assign DBs
6.  Execution Engine:
    *   Query Postgres
    *   Query MySQL
7.  Merge results
8.  Return to user

**1.6 Define Interfaces (Core Contracts)**

These are the **heart of extensibility**:

**Driver Interface**

type Driver interface {  
Connect(connStr string) error  
Query(query string, args ...interface{}) (Result, error)  
Exec(query string, args ...interface{}) error  
}

**Router Interface**

type Router interface {  
Route(plan ExecutionPlan) (\[\]Route, error)  
}

**Parser Interface**

type Parser interface {  
Parse(query string) (AST, error)  
}

**Planner Interface**

type Planner interface {  
Plan(ast AST) (ExecutionPlan, error)  
}

**1.7 Define Project Structure**

Recommended structure:

unidb-go/  
│  
├── api/  
├── parser/  
├── planner/  
├── router/  
├── security/  
├── execution/  
├── pool/  
├── drivers/  
│ ├── postgres/  
│ ├── mysql/  
│ ├── mongodb/  
│  
├── internal/  
├── pkg/  
├── tests/  
└── examples/

**1.8 Technology Decisions**

**Language:**

*   Go (goroutines + performance)

**Libraries:**

*   database/sql
*   Vitess SQL parser
*   gRPC (optional)

**Infra:**

*   Docker (for multi-DB testing)

**1.9 Define MVP Scope (CRUCIAL)**

Start small:

**Phase 1 MVP:**

*   PostgreSQL + MySQL only
*   Basic query routing
*   No federation yet

**Phase 2:**

*   Add MongoDB
*   Add simple federation

**Phase 3:**

*   Add AI optimization
*   Add advanced security

**1.10 Define Success Metrics**

*   Query latency overhead
*   Throughput (req/sec)
*   Accuracy of routing
*   Security detection rate

**1.11 Deliverables of This Phase**

By the end of Foundation phase, you should have:

✅ Architecture diagram  
✅ Defined interfaces  
✅ Project structure  
✅ Design document (important for resumes + research)  
✅ Basic skeleton code (no heavy logic yet)

**2\. Driver Abstraction & Unified Interface (UniDB-Go)**

This phase builds the **core abstraction layer**—the equivalent of JDBC—so every database behaves like one unified system.

**2.1 Objective of This Phase**

Design a **single, consistent interface** that:

*   Works across SQL + NoSQL
*   Hides driver-specific complexity
*   Supports future extensibility
*   Enables routing, federation, and security layers

👉 Output of this phase = **A working pluggable driver system + unified API**

**2.2 Core Design Principles**

**1\. Strict Abstraction Boundary**

*   Application should NEVER know:
    *   which DB is used
    *   which driver is used

**2\. Capability-Based Design**

Not all DBs support:

*   JOINs
*   transactions
*   schemas

👉 So define **capabilities per driver**

**3\. Zero-Leak Interface**

Avoid exposing:

*   SQL-specific types
*   Mongo-specific types

**4\. Extensibility First**

Adding a new DB should require:

*   ONLY implementing the Driver interface

**2.3 Define the Unified Interfaces (STRICT CONTRACTS)**

**2.3.1 Core DB Interface (User-Facing)**

type DB interface {  
Query(ctx context.Context, query string, args ...any) (Result, error)  
Exec(ctx context.Context, query string, args ...any) (ExecResult, error)  
  
BeginTx(ctx context.Context) (Tx, error)  
  
Close() error  
}

**2.3.2 Transaction Interface**

type Tx interface {  
Query(ctx context.Context, query string, args ...any) (Result, error)  
Exec(ctx context.Context, query string, args ...any) (ExecResult, error)  
  
Commit() error  
Rollback() error  
}

**2.3.3 Result Interface (DB-Agnostic)**

type Result interface {  
Columns() \[\]string  
Next() bool  
Scan(dest ...any) error  
Close() error  
}

**2.3.4 Exec Result**

type ExecResult interface {  
RowsAffected() int64  
LastInsertId() (int64, error)  
}

**2.4 Internal Driver Interface (CRITICAL LAYER)**

This is what all DB drivers MUST implement:

type Driver interface {  
Connect(config Config) (Connection, error)  
Capabilities() Capabilities  
}

**2.4.1 Connection Interface**

type Connection interface {  
Query(ctx context.Context, query string, args ...any) (Result, error)  
Exec(ctx context.Context, query string, args ...any) (ExecResult, error)  
  
BeginTx(ctx context.Context) (Tx, error)  
  
Close() error  
}

**2.4.2 Capabilities Struct**

type Capabilities struct {  
SupportsSQL bool  
SupportsTransactions bool  
SupportsJoins bool  
SupportsAggregation bool  
}

👉 Example:

*   PostgreSQL → all true
*   MongoDB → no joins (limited), no SQL

**2.5 Driver Registration System (PLUGIN SYSTEM)**

**2.5.1 Global Driver Registry**

var driverRegistry = map\[string\]Driver{}

**2.5.2 Register Function**

func RegisterDriver(name string, driver Driver) {  
driverRegistry\[name\] = driver  
}

**2.5.3 Get Driver**

func GetDriver(name string) (Driver, error) {  
d, ok := driverRegistry\[name\]  
if !ok {  
return nil, fmt.Errorf("driver not found: %s", name)  
}  
return d, nil  
}

**2.5.4 Example Registration (Postgres)**

func init() {  
RegisterDriver("postgres", &PostgresDriver{})  
}

**2.6 Connection Factory (ENTRY POINT)**

**2.6.1 Connect Function**

func Connect(connStr string) (DB, error) {  
cfg := ParseConnectionString(connStr)  
  
driver, err := GetDriver(cfg.Driver)  
if err != nil {  
return nil, err  
}  
  
conn, err := driver.Connect(cfg)  
if err != nil {  
return nil, err  
}  
  
return NewUnifiedDB(conn), nil  
}

**2.6.2 Connection String Format**

Standardize format:

postgres://user:pass@localhost:5432/dbname  
mysql://user:pass@localhost:3306/dbname  
mongodb://localhost:27017/db

**2.7 Unified DB Wrapper (IMPORTANT)**

Wraps raw driver connection into system pipeline:

type UnifiedDB struct {  
conn Connection  
}

**2.7.1 Query Flow**

func (db \*UnifiedDB) Query(ctx context.Context, q string, args ...any) (Result, error) {  
// Later hooks:  
// - security  
// - routing  
// - parsing  
  
return db.conn.Query(ctx, q, args...)  
}

👉 For now: direct pass-through  
👉 Later: plug pipeline here

**2.8 SQL vs NoSQL Handling Strategy**

**Problem**

*   SQL uses structured queries
*   NoSQL uses documents / commands

**Solution: Query Normalization Layer**

Define internal query representation:

type UnifiedQuery struct {  
Type string // SELECT, INSERT, FIND  
Raw string  
Params \[\]any  
TargetDB string  
}

**Mongo Example Mapping**

User writes:

db.Query("FIND users WHERE age > ?", 25)

Driver translates to:

collection.Find({"age": {"$gt": 25}})

**2.9 Error Handling Standardization**

**Define Unified Errors**

var (  
ErrConnectionFailed = errors.New("connection failed")  
ErrQueryFailed = errors.New("query failed")  
ErrNotSupported = errors.New("operation not supported")  
)

**Wrap Driver Errors**

return nil, fmt.Errorf("%w: %v", ErrQueryFailed, err)

**2.10 Type Normalization (VERY IMPORTANT)**

Different DBs return:

*   int64, float64, \[\]byte, BSON, JSON

**Solution: Internal Type System**

type Value any

OR stricter:

type Value struct {  
Type string  
Data any  
}

**2.11 Minimal Driver Implementations (MVP)**

**PostgreSQL Driver**

*   Use database/sql
*   Wrap:
    *   sql.DB
    *   sql.Rows

**MySQL Driver**

*   Same abstraction as PostgreSQL

**MongoDB Driver**

*   Use official Mongo driver
*   Convert:
    *   BSON → unified Result

**2.12 Testing Strategy (MANDATORY)**

**Unit Tests**

*   Driver registration
*   Connection creation
*   Query execution

**Integration Tests**

Use Docker:

*   Postgres
*   MySQL
*   MongoDB

**Test Cases**

*   Same query across DBs
*   Transaction behavior
*   Error cases

**2.13 Deliverables of This Phase**

By end of this phase:

✅ Unified DB interface  
✅ Driver interface implemented  
✅ PostgreSQL driver working  
✅ MySQL driver working  
✅ Basic Mongo driver  
✅ Connection factory  
✅ Driver registry system  
✅ Basic tests

**2.14 Common Pitfalls (Avoid These)**

❌ Mixing DB logic in API layer  
❌ Hardcoding DB types  
❌ Ignoring NoSQL differences  
❌ No capability checks  
❌ Poor error abstraction

**2.15 Definition of Done (STRICT)**

You are DONE when:

*   This works:

db, \_ := unidb.Connect("postgres://localhost:5432/test")  
db.Query(ctx, "SELECT \* FROM users")

AND:

db, \_ := unidb.Connect("mongodb://localhost:27017/test")  
db.Query(ctx, "FIND users WHERE age > ?", 25)

AND both use the **same API without changes**

**3\. Core API Development (UniDB-Go)**

Design and implement the **public-facing API** that developers will actually use.

This layer must feel as simple as database/sql, but be powerful enough to support **routing, federation, and security later**.

**3.1 Objective of This Phase**

Build a **clean, stable, production-grade API** that:

*   Hides all internal complexity
*   Feels familiar to Go developers
*   Supports SQL + NoSQL uniformly
*   Is extensible for future features (routing, AI, federation)

👉 Output: A **developer-friendly API** that works across multiple databases.

**3.2 API Design Philosophy**

**1\. Minimal but Powerful**

Expose only essential methods:

*   Connect
*   Query
*   Exec
*   BeginTx

**2\. Context-First Design (MANDATORY)**

Every operation must support:

context.Context

This enables:

*   cancellation
*   timeouts
*   tracing

**3\. Consistent Behavior Across Databases**

*   Same function signatures
*   Same result handling

**4\. Pipeline-Ready**

Even if not implemented yet, API should allow:

*   security hooks
*   query parsing
*   routing

**3.3 Public API Surface (FINAL SPEC)**

**3.3.1 Connect Function**

**Purpose:**

Entry point for all applications.

func Connect(connStr string, opts ...Option) (\*DB, error)

**Responsibilities:**

*   Parse connection string
*   Select driver
*   Initialize connection pool
*   Apply options

**Example Usage:**

db, err := unidb.Connect("postgres://localhost:5432/test")  
if err != nil {  
panic(err)  
}

**3.3.2 DB Struct (Core Object)**

type DB struct {  
conn Connection  
config Config  
middleware \[\]Middleware  
}

**Responsibilities:**

*   Main user interface
*   Entry point for all operations
*   Middleware execution

**3.4 Query API**

**3.4.1 Query Method**

func (db \*DB) Query(ctx context.Context, query string, args ...any) (Result, error)

**Responsibilities:**

1.  Validate input
2.  Pass through middleware pipeline
3.  Execute query
4.  Return unified result

**Internal Flow:**

User Query  
↓  
Middleware Chain  
↓  
Parser (future)  
↓  
Router (future)  
↓  
Driver Execution  
↓  
Result

**Example Usage:**

rows, err := db.Query(ctx, "SELECT \* FROM users WHERE id = ?", 5)

**3.4.2 QueryRow (Optional but Recommended)**

func (db \*DB) QueryRow(ctx context.Context, query string, args ...any) Row

**Behavior:**

*   Returns single row
*   Internally calls Query
*   Stops after first result

**3.5 Exec API**

**3.5.1 Exec Method**

func (db \*DB) Exec(ctx context.Context, query string, args ...any) (ExecResult, error)

**Used For:**

*   INSERT
*   UPDATE
*   DELETE
*   Non-query operations

**Example:**

res, err := db.Exec(ctx, "UPDATE users SET name=? WHERE id=?", "Alan", 1)

**3.6 Transaction API**

**3.6.1 Begin Transaction**

func (db \*DB) BeginTx(ctx context.Context, opts \*TxOptions) (Tx, error)

**TxOptions:**

type TxOptions struct {  
Isolation string  
ReadOnly bool  
}

**3.6.2 Transaction Interface**

type Tx interface {  
Query(ctx context.Context, query string, args ...any) (Result, error)  
Exec(ctx context.Context, query string, args ...any) (ExecResult, error)  
  
Commit() error  
Rollback() error  
}

**Example Usage:**

tx, \_ := db.BeginTx(ctx, nil)  
  
tx.Exec(ctx, "INSERT INTO users(name) VALUES(?)", "John")  
  
tx.Commit()

**Important:**

*   If DB doesn't support transactions → return ErrNotSupported

**3.7 Middleware System (CRITICAL FOR FUTURE FEATURES)**

**3.7.1 Middleware Definition**

type Middleware func(next Handler) Handler

**3.7.2 Handler Definition**

type Handler func(ctx context.Context, query string, args ...any) (Result, error)

**3.7.3 Middleware Chain Execution**

func (db \*DB) execute(ctx context.Context, q string, args ...any) (Result, error) {  
handler := db.finalHandler()  
  
for i := len(db.middleware)-1; i >= 0; i-- {  
handler = db.middleware\[i\](handler)  
}  
  
return handler(ctx, q, args...)  
}

**Future Middleware Examples:**

*   Security engine
*   Query logger
*   Metrics collector
*   Query optimizer

**3.8 Configuration System**

**3.8.1 Config Struct**

type Config struct {  
Driver string  
Host string  
Port int  
Database string  
Username string  
Password string  
PoolSize int  
}

**3.8.2 Functional Options Pattern**

type Option func(\*DB)

**Example:**

func WithMaxPool(size int) Option {  
return func(db \*DB) {  
db.config.PoolSize = size  
}  
}

**Usage:**

db, \_ := unidb.Connect(connStr, WithMaxPool(20))

**3.9 Error Handling Strategy**

**Standard Errors:**

var (  
ErrInvalidQuery = errors.New("invalid query")  
ErrNotSupported = errors.New("not supported")  
ErrConnectionFail = errors.New("connection failed")  
)

**Rules:**

*   Wrap all internal errors
*   Never expose raw driver errors

**3.10 Logging & Observability Hooks**

**Add Hooks:**

type Logger interface {  
Log(query string, duration time.Duration, err error)  
}

**Integration:**

db.Use(LoggerMiddleware(logger))

**3.11 Concurrency & Thread Safety**

**Requirements:**

*   DB must be safe for concurrent use
*   Use:
    *   mutexes where needed
    *   connection pool for parallel queries

**Rule:**

❗ Never store query-specific state in DB struct

**3.12 Resource Management**

**Close Method:**

func (db \*DB) Close() error

**Responsibilities:**

*   Close all connections
*   Cleanup resources

**3.13 Folder Structure for API Layer**

api/  
├── db.go  
├── connect.go  
├── query.go  
├── exec.go  
├── tx.go  
├── middleware.go  
├── config.go  
├── errors.go  
└── options.go

**3.14 Testing Strategy**

**Unit Tests:**

*   Connect
*   Query
*   Exec
*   Transactions

**Mock Driver:**

Create fake driver:

type MockDriver struct{}

**Test Cases:**

*   Successful query
*   Invalid query
*   Timeout using context
*   Concurrent queries

**3.15 Deliverables of This Phase**

By the end:

✅ Connect() working  
✅ Query() working across DBs  
✅ Exec() working  
✅ Transactions implemented  
✅ Middleware system ready  
✅ Config system ready  
✅ Error handling standardized  
✅ Thread-safe API

**3.16 Definition of Done (STRICT)**

You are DONE when this works identically:

db, \_ := unidb.Connect("postgres://localhost:5432/test")  
db.Query(ctx, "SELECT \* FROM users")

AND:

db, \_ := unidb.Connect("mysql://localhost:3306/test")  
db.Exec(ctx, "INSERT INTO users(name) VALUES(?)", "Alice")

AND:

tx, \_ := db.BeginTx(ctx, nil)  
tx.Exec(ctx, "UPDATE users SET name=? WHERE id=?", "Bob", 1)  
tx.Commit()

**3.17 Common Pitfalls**

❌ Overloading API with too many methods  
❌ Leaking driver-specific behavior  
❌ Ignoring context cancellation  
❌ No middleware (blocks future features)  
❌ Tight coupling with drivers

**4\. Query Parsing & AST Construction (UniDB-Go)**

This phase turns raw queries into a **machine-understandable structure (AST)**—the foundation for:

*   query routing
*   optimization
*   federation
*   security analysis

**4.1 Objective of This Phase**

Build a **robust parsing layer** that:

*   Converts SQL → AST
*   Supports multiple dialects (Postgres/MySQL initially)
*   Enables downstream modules (planner, router)
*   Is extensible for NoSQL translation

👉 Output: **A fully working parser + AST representation layer**

**4.2 Why AST is Critical**

Without AST, your system:

*   cannot split queries
*   cannot optimize
*   cannot detect malicious patterns
*   cannot support cross-database joins

👉 AST = **“intermediate representation” like in compilers**

**4.3 Tool Selection (VERY IMPORTANT)**

**Primary Tool: Vitess SQL Parser**

Use:

*   **Vitess SQL Parser**

**Why Vitess?**

✔ Written in Go (native integration)  
✔ Production-grade (used in large-scale systems)  
✔ Supports MySQL dialect (extendable to others)  
✔ Generates AST directly  
✔ Handles complex queries (JOINs, subqueries)

**Alternative (Not Recommended Initially)**

*   ANTLR (too heavy for MVP)
*   Writing your own parser (too complex)

👉 Decision: **Start with Vitess**

**4.4 High-Level Architecture**

Raw Query (string)  
↓  
Parser Layer (Vitess)  
↓  
Vitess AST  
↓  
UniDB AST (normalized)  
↓  
Planner / Router / Security

**4.5 Two-Level AST Strategy (CRITICAL DESIGN)**

**Level 1: External AST (Vitess)**

*   Direct output from parser
*   Complex, DB-specific

**Level 2: Internal AST (UniDB AST)**

👉 You MUST convert to your own format

**Why?**

*   Normalize across databases
*   Simplify planner logic
*   Support NoSQL later

**4.6 Define Internal AST Structure**

**4.6.1 Root Node**

type QueryAST struct {  
Type string // SELECT, INSERT, UPDATE, DELETE  
Tables \[\]TableNode  
Fields \[\]FieldNode  
Conditions \[\]ConditionNode  
Joins \[\]JoinNode  
Limit \*int  
}

**4.6.2 Table Node**

type TableNode struct {  
Name string  
Database string // postgres, mysql, etc.  
Alias string  
}

**4.6.3 Field Node**

type FieldNode struct {  
Name string  
Table string  
Alias string  
Aggregate string // COUNT, SUM, etc.  
}

**4.6.4 Condition Node**

type ConditionNode struct {  
Left string  
Operator string  
Right any  
}

**4.6.5 Join Node**

type JoinNode struct {  
Type string // INNER, LEFT  
LeftTable string  
RightTable string  
On ConditionNode  
}

**4.7 Parsing Pipeline Implementation**

**4.7.1 Step 1: Parse Query Using Vitess**

import "vitess.io/vitess/go/vt/sqlparser"  
  
stmt, err := sqlparser.Parse(query)

**4.7.2 Step 2: Type Switch on Statement**

switch node := stmt.(type) {  
case \*sqlparser.Select:  
return parseSelect(node)  
case \*sqlparser.Insert:  
return parseInsert(node)  
}

**4.7.3 Step 3: Convert to Internal AST**

**Example: SELECT Query**

SELECT name FROM users WHERE id = 5

**Conversion Function:**

func parseSelect(sel \*sqlparser.Select) (\*QueryAST, error) {  
ast := &QueryAST{  
Type: "SELECT",  
}  
  
// Extract fields  
for \_, expr := range sel.SelectExprs {  
col := expr.(\*sqlparser.AliasedExpr)  
ast.Fields = append(ast.Fields, FieldNode{  
Name: sqlparser.String(col.Expr),  
})  
}  
  
// Extract table  
for \_, tbl := range sel.From {  
tableExpr := tbl.(\*sqlparser.AliasedTableExpr)  
ast.Tables = append(ast.Tables, TableNode{  
Name: sqlparser.String(tableExpr.Expr),  
})  
}  
  
return ast, nil  
}

**4.8 Multi-Database Query Detection**

**Example:**

SELECT \* FROM postgres.users u  
JOIN mysql.orders o ON u.id = o.user\_id

**Detection Logic:**

*   Parse table names:
    *   postgres.users
    *   mysql.orders

**Output:**

TableNode{  
Name: "users",  
Database: "postgres",  
}

👉 This is **critical for federation later**

**4.9 Query Validation Layer**

**Validate After Parsing:**

*   Missing tables
*   Invalid syntax
*   Unsupported operations

**Example:**

if len(ast.Tables) == 0 {  
return nil, ErrInvalidQuery  
}

**4.10 Error Handling**

**Types of Errors:**

1.  Syntax errors (from parser)
2.  Semantic errors (your validation)
3.  Unsupported queries

**Wrap Errors:**

return nil, fmt.Errorf("parse error: %w", err)

**4.11 Extend for NoSQL (Forward Compatibility)**

**Strategy:**

Convert SQL-like queries → NoSQL operations

**Example:**

SELECT \* FROM users WHERE age > 25

→ Mongo:

{ "age": { "$gt": 25 } }

**Add to AST:**

type QueryAST struct {  
IsNoSQLCompatible bool  
}

**4.12 Performance Considerations**

**Cache Parsed Queries**

var queryCache = map\[string\]\*QueryAST{}

**Use Hashing:**

key := hash(query)

👉 Avoid parsing same query repeatedly

**4.13 Testing Strategy**

**Unit Tests:**

*   Simple SELECT
*   JOIN queries
*   WHERE conditions
*   Invalid queries

**Edge Cases:**

*   Nested queries
*   Aliases
*   Aggregations

**Example Test:**

query := "SELECT name FROM users WHERE id = 1"  
ast, err := parser.Parse(query)  
  
assert.Equal(t, "SELECT", ast.Type)  
assert.Equal(t, "users", ast.Tables\[0\].Name)

**4.14 Folder Structure**

parser/  
├── parser.go  
├── select.go  
├── insert.go  
├── update.go  
├── delete.go  
├── ast.go  
├── converter.go  
├── cache.go  
└── errors.go

**4.15 Deliverables of This Phase**

By end:

✅ SQL parsing using Vitess  
✅ Internal AST structure defined  
✅ SELECT queries fully supported  
✅ Basic JOIN parsing  
✅ Multi-DB detection working  
✅ Query validation implemented  
✅ Parser test suite complete

**4.16 Definition of Done (STRICT)**

You are DONE when:

Input:

SELECT u.name, o.total  
FROM postgres.users u  
JOIN mysql.orders o ON u.id = o.user\_id  
WHERE u.id = 5

Output:

QueryAST{  
Type: "SELECT",  
Tables: \[  
{Name: "users", Database: "postgres"},  
{Name: "orders", Database: "mysql"},  
\],  
Joins: \[...\],  
Conditions: \[...\],  
}

**4.17 Common Pitfalls**

❌ Using only raw SQL strings (no AST)  
❌ Not normalizing AST  
❌ Ignoring aliases  
❌ Ignoring multi-DB syntax  
❌ Overcomplicating AST early

**5\. Query Planning & Intelligent Routing (UniDB-Go)**

This is the **brain of your system**—where raw parsed queries (AST) are transformed into **optimized execution plans** and routed to the right databases.

**5.1 Objective of This Phase**

Build a **Query Planner + Intelligent Router** that:

*   Decides **which database(s)** to use
*   Splits queries for **multi-database execution**
*   Determines **execution order & strategy**
*   Optimizes for **performance, latency, and load**

👉 Output: A **fully functional planning engine + routing system**

**5.2 High-Level Flow**

QueryAST  
↓  
Query Analyzer  
↓  
Logical Plan  
↓  
Optimizer  
↓  
Execution Plan  
↓  
Router  
↓  
Execution Engine

**5.3 Core Concepts You Must Implement**

**1\. Logical Plan**

Abstract representation of query execution

**2\. Physical Plan (Execution Plan)**

Concrete steps:

*   which DB
*   in what order
*   how to combine results

**3\. Cost-Based Decisions (basic version first)**

Choose best DB based on:

*   latency
*   load
*   capabilities

**5.4 Define Execution Plan Structure**

**5.4.1 Execution Plan**

type ExecutionPlan struct {  
Steps \[\]ExecutionStep  
}

**5.4.2 Execution Step**

type ExecutionStep struct {  
ID int  
Type string // SCAN, JOIN, FILTER  
Database string  
Query string  
DependsOn \[\]int  
}

**Example:**

Step 1 → Query postgres.users  
Step 2 → Query mysql.orders  
Step 3 → Join results

**5.5 Query Analyzer (FIRST STAGE)**

**Responsibilities:**

*   Inspect AST
*   Identify:
    *   tables
    *   joins
    *   filters
    *   aggregations

**Example:**

Input AST:

Tables: postgres.users, mysql.orders  
Join: users.id = orders.user\_id

**Output:**

type QueryMetadata struct {  
Tables \[\]TableNode  
IsMultiDB bool  
HasJoin bool  
Filters \[\]ConditionNode  
}

**5.6 Database Selection Strategy**

**5.6.1 Rule-Based Routing (MVP)**

Start simple:

| Query Type | Route To |
| --- | --- |
| SELECT (single table) | That DB |
| JOIN across DBs | Federation |
| INSERT | Primary DB |
| Analytics query | Warehouse DB (future) |

**5.6.2 Capability-Based Routing**

Use driver capabilities:

if !driver.Capabilities().SupportsJoins {  
// fallback strategy  
}

**5.6.3 Metric-Based Routing (Advanced)**

Track runtime metrics:

type DBMetrics struct {  
Latency time.Duration  
Load float64  
ErrorRate float64  
}

**Decision Example:**

if metrics\["postgres"\].Latency < metrics\["mysql"\].Latency {  
use("postgres")  
}

**5.7 Query Splitting (CRITICAL FEATURE)**

**Case 1: Single Database Query**

SELECT \* FROM users

👉 No splitting needed

**Case 2: Multi-Database Query**

SELECT u.name, o.total  
FROM postgres.users u  
JOIN mysql.orders o  
ON u.id = o.user\_id

**Splitting Strategy**

**Step 1: Identify tables per DB**

postgres → users  
mysql → orders

**Step 2: Generate subqueries**

\-- Query 1  
SELECT id, name FROM users  
  
\-- Query 2  
SELECT user\_id, total FROM orders

**Step 3: Define merge step**

JOIN users.id = orders.user\_id (in memory)

**Implementation Function**

func SplitQuery(ast \*QueryAST) (\[\]SubQuery, error)

**SubQuery Struct**

type SubQuery struct {  
Database string  
Query string  
}

**5.8 Join Execution Strategy**

**Options:**

**1\. In-Memory Join (MVP)**

*   Fetch data from both DBs
*   Join in Go

✔ Easy  
❌ Not scalable for huge data

**2\. Pushdown Join (Advanced)**

*   If both tables in same DB → let DB handle join

**3\. Hybrid Join (Future)**

*   Partial filtering in DB
*   Final merge in middleware

**5.9 Execution Planning Algorithm**

**Step-by-step:**

**Step 1: Analyze AST**

meta := Analyze(ast)

**Step 2: Check if Multi-DB**

if meta.IsMultiDB {  
return planFederatedQuery(ast)  
}

**Step 3: Generate Plan**

plan := ExecutionPlan{}

**Step 4: Add Steps**

plan.Steps = append(plan.Steps, ExecutionStep{  
ID: 1,  
Type: "SCAN",  
Database: "postgres",  
Query: "SELECT id, name FROM users",  
})

**Step 5: Add Join Step**

plan.Steps = append(plan.Steps, ExecutionStep{  
ID: 3,  
Type: "JOIN",  
DependsOn: \[\]int{1, 2},  
})

**5.10 Intelligent Router**

**Router Interface**

type Router interface {  
Route(plan \*ExecutionPlan) (\[\]Route, error)  
}

**Route Struct**

type Route struct {  
StepID int  
Database string  
}

**Routing Logic**

**Step 1: Iterate Steps**

for \_, step := range plan.Steps {

**Step 2: Assign Database**

route := Route{  
StepID: step.ID,  
Database: step.Database,  
}

**Future Enhancement: Smart Routing**

Use:

*   latency
*   load
*   data locality

**5.11 Optimization Layer**

**Basic Optimizations**

**1\. Filter Pushdown**

WHERE age > 30

👉 Execute in DB, not in Go

**2\. Column Pruning**

Only fetch required fields

**3\. Query Rewriting**

Simplify query before execution

**5.12 Caching Execution Plans**

**Cache Plans:**

var planCache map\[string\]\*ExecutionPlan

**Key:**

hash(query)

👉 Avoid recomputing plans

**5.13 Handling Edge Cases**

**1\. Unsupported Queries**

Return:

ErrNotSupported

**2\. Missing Tables**

Validation failure

**3\. Cross-DB Transactions**

Not supported initially

**5.14 Testing Strategy**

**Unit Tests:**

*   Single DB routing
*   Multi DB splitting
*   Join planning

**Integration Tests:**

*   PostgreSQL + MySQL together
*   Verify correct results

**Performance Tests:**

*   Query latency
*   Routing overhead

**5.15 Folder Structure**

planner/  
├── analyzer.go  
├── planner.go  
├── splitter.go  
├── optimizer.go  
├── plan.go  
├── router.go  
├── metrics.go  
└── cache.go

**5.16 Deliverables of This Phase**

By end:

✅ Query Analyzer working  
✅ Execution Plan generator  
✅ Query splitting implemented  
✅ Basic join strategy (in-memory)  
✅ Rule-based routing working  
✅ Router implemented  
✅ Plan caching

**5.17 Definition of Done (STRICT)**

You are DONE when:

Input:

SELECT u.name, o.total  
FROM postgres.users u  
JOIN mysql.orders o  
ON u.id = o.user\_id

Output Plan:

Step 1 → Query postgres.users  
Step 2 → Query mysql.orders  
Step 3 → Join results in memory

AND system executes correctly.

**5.18 Common Pitfalls**

❌ Overengineering cost-based optimizer too early  
❌ Not separating logical vs physical plan  
❌ Ignoring DB capabilities  
❌ Fetching too much data  
❌ No plan caching

**6\. Cross-Database Query Federation (UniDB-Go)**

Enable distributed queries across multiple databases and **merge results into a single response**.

This is the feature that makes UniDB-Go truly **“universal”**.

**6.1 Objective of This Phase**

Build a **federation engine** that:

*   Executes queries across **multiple heterogeneous databases**
*   Supports **cross-database JOINs**
*   Merges results **correctly and efficiently**
*   Works transparently through the same API

👉 Output: A working **distributed query execution + result merging system**

**6.2 What is Query Federation?**

Example:

SELECT u.name, o.total  
FROM postgres.users u  
JOIN mysql.orders o  
ON u.id = o.user\_id

👉 Your system should:

1.  Query PostgreSQL
2.  Query MySQL
3.  Merge results
4.  Return unified output

**6.3 High-Level Federation Architecture**

Execution Plan  
↓  
Subquery Executor  
↓  
Parallel Execution Layer  
↓  
Intermediate Results  
↓  
Merge Engine (JOIN/GROUP/FILTER)  
↓  
Final Result

**6.4 Federation Execution Flow (Step-by-Step)**

**Step 1: Receive Execution Plan**

From Phase 5:

Step 1 → postgres.users  
Step 2 → mysql.orders  
Step 3 → JOIN

**Step 2: Execute Subqueries in Parallel**

Use goroutines:

var wg sync.WaitGroup  
  
for \_, step := range plan.Steps {  
if step.Type == "SCAN" {  
wg.Add(1)  
go executeStep(step)  
}  
}  
wg.Wait()

**Step 3: Collect Intermediate Results**

Store results:

type IntermediateResult struct {  
StepID int  
Rows \[\]Row  
}

**Step 4: Pass to Merge Engine**

final := Merge(results)

**6.5 Subquery Execution Layer**

**6.5.1 Execution Function**

func executeStep(step ExecutionStep) (\[\]Row, error) {  
conn := getConnection(step.Database)  
res, err := conn.Query(context.Background(), step.Query)  
return convertToRows(res), err  
}

**6.5.2 Row Representation (UNIFIED)**

type Row map\[string\]interface{}

**Example:**

{  
"id": 1,  
"name": "Alice",  
}

**6.6 Merge Engine (CORE COMPONENT)**

This is where the real complexity lies.

**6.6.1 Supported Operations (MVP)**

Start with:

✔ INNER JOIN  
✔ LEFT JOIN (optional later)  
✔ WHERE filtering  
✔ Projection (select fields)

**6.7 Join Algorithm Implementation**

**6.7.1 Hash Join (RECOMMENDED)**

**Why Hash Join?**

✔ Fast  
✔ Simple  
✔ Works in-memory

**Algorithm Steps**

**Step 1: Build Hash Map (Right Table)**

hash := make(map\[any\]\[\]Row)  
  
for \_, row := range rightRows {  
key := row\["user\_id"\]  
hash\[key\] = append(hash\[key\], row)  
}

**Step 2: Probe (Left Table)**

var result \[\]Row  
  
for \_, l := range leftRows {  
key := l\["id"\]  
matches := hash\[key\]  
  
for \_, r := range matches {  
merged := mergeRows(l, r)  
result = append(result, merged)  
}  
}

**6.7.2 Merge Rows**

func mergeRows(a, b Row) Row {  
res := Row{}  
  
for k, v := range a {  
res\["a."+k\] = v  
}  
  
for k, v := range b {  
res\["b."+k\] = v  
}  
  
return res  
}

**6.8 Handling Column Conflicts**

**Problem:**

users.id AND orders.id

**Solution:**

Prefix columns:

users.id → u.id  
orders.id → o.id

**Enforce in AST + Planner**

**6.9 Filtering After Join**

**Example:**

WHERE u.id = 5

**Apply:**

if row\["u.id"\] == 5 {  
keep  
}

**6.10 Projection (SELECT fields)**

**Only return requested fields:**

func project(row Row, fields \[\]FieldNode) Row

**6.11 Parallel Execution Optimization**

**Use Goroutines + Channels:**

ch := make(chan IntermediateResult)  
  
go func() {  
res, \_ := executeStep(step)  
ch <- IntermediateResult{StepID: step.ID, Rows: res}  
}()

**6.12 Memory Management (IMPORTANT)**

**Problem:**

Large datasets = high memory usage

**Solutions:**

**1\. Limit rows (MVP)**

LIMIT 1000

**2\. Streaming (Advanced)**

Process rows in chunks instead of loading all

**6.13 Error Handling in Federation**

**Cases:**

*   One DB fails
*   Partial results
*   Timeout

**Strategy:**

**MVP:**

*   Fail entire query

**Advanced:**

*   Partial results + warnings

**6.14 Federation Coordinator**

**Central controller:**

type FederationEngine struct {  
executor Executor  
merger Merger  
}

**Execution:**

func (f \*FederationEngine) Execute(plan \*ExecutionPlan) (Result, error)

**6.15 Integration with Previous Phases**

| Component | Role |
| --- | --- |
| Parser | Builds AST |
| Planner | Creates execution plan |
| Router | Assigns DB |
| Federation Engine | Executes + merges |

**6.16 Testing Strategy**

**Unit Tests:**

*   Join logic
*   Merge correctness
*   Column mapping

**Integration Tests:**

*   Postgres + MySQL
*   Verify correct join output

**Edge Cases:**

*   Empty results
*   No matches
*   Duplicate keys

**6.17 Folder Structure**

federation/  
├── engine.go  
├── executor.go  
├── merger.go  
├── join.go  
├── filter.go  
├── projection.go  
├── memory.go  
└── errors.go

**6.18 Deliverables of This Phase**

By end:

✅ Parallel subquery execution  
✅ Intermediate result storage  
✅ Hash join implementation  
✅ Result merging engine  
✅ Column conflict handling  
✅ Filtering + projection  
✅ Federation engine integrated

**6.19 Definition of Done (STRICT)**

You are DONE when:

This works:

db.Query(ctx, \`  
SELECT u.name, o.total  
FROM postgres.users u  
JOIN mysql.orders o  
ON u.id = o.user\_id  
\`)

AND returns correct merged output.

**6.20 Common Pitfalls**

❌ Loading too much data into memory  
❌ Ignoring column conflicts  
❌ Incorrect join logic  
❌ Not parallelizing execution  
❌ Skipping filtering optimization

**7\. Security Engine & Threat Detection (UniDB-Go)**

Build mechanisms to detect **SQL injection, anomalous queries, and data exfiltration patterns**—directly inside your database middleware.

This layer makes UniDB-Go **not just a connector, but a defensive system**.

**7.1 Objective of This Phase**

Design and implement a **real-time query security engine** that:

*   Inspects every query before execution
*   Detects malicious or suspicious behavior
*   Blocks, logs, or flags queries
*   Integrates seamlessly into the middleware pipeline

👉 Output: A **pluggable, low-latency security engine**

**7.2 High-Level Architecture**

Incoming Query  
↓  
Parser (AST)  
↓  
Security Engine  
├── Rule Engine (Injection detection)  
├── Behavior Analyzer (Anomaly detection)  
├── Data Leak Detector (Exfiltration)  
↓  
Decision Engine  
↓  
(ALLOW / BLOCK / FLAG)  
↓  
Execution Pipeline

**7.3 Core Components**

**1\. Rule-Based Detection Engine (SQL Injection)**

**2\. Anomaly Detection Engine (Behavioral)**

**3\. Data Exfiltration Detection Engine**

**4\. Decision Engine**

**5\. Logging & Alert System**

**7.4 Integration with API Layer (CRITICAL)**

**Add as Middleware**

db.Use(SecurityMiddleware(securityEngine))

**Middleware Flow:**

func SecurityMiddleware(engine \*SecurityEngine) Middleware {  
return func(next Handler) Handler {  
return func(ctx context.Context, query string, args ...any) (Result, error) {  
decision := engine.Analyze(query)  
  
if decision.Block {  
return nil, ErrBlockedQuery  
}  
  
return next(ctx, query, args...)  
}  
}  
}

**7.5 SQL Injection Detection**

**7.5.1 Approach: Hybrid Detection**

Use:

*   Pattern matching (fast)
*   AST analysis (accurate)

**7.5.2 Pattern-Based Detection (MVP)**

**Detect Common Patterns:**

| Pattern | Example |
| --- | --- |
| Always true | 1=1 |
| Comment injection | --, /* */ |
| Union attack | UNION SELECT |
| Tautology | OR 'a'='a' |

**Implementation**

var injectionPatterns = \[\]string{  
" OR 1=1",  
"--",  
"/\*",  
"UNION SELECT",  
}

func detectInjection(query string) bool {  
q := strings.ToUpper(query)  
  
for \_, pattern := range injectionPatterns {  
if strings.Contains(q, pattern) {  
return true  
}  
}  
return false  
}

**7.5.3 AST-Based Detection (ADVANCED)**

**Detect suspicious logic:**

Example:

WHERE id = 1 OR 1=1

**AST Check:**

func detectTautology(ast \*QueryAST) bool {  
for \_, cond := range ast.Conditions {  
if cond.Left == cond.Right {  
return true  
}  
}  
return false  
}

**7.6 Anomalous Query Detection**

**Goal: Detect unusual behavior**

**7.6.1 Metrics to Track**

type QueryStats struct {  
Frequency int  
AvgLatency time.Duration  
LastSeen time.Time  
}

**7.6.2 User Behavior Tracking**

type UserProfile struct {  
TypicalTables \[\]string  
AvgQuerySize int  
QueryPatterns map\[string\]int  
}

**7.6.3 Detection Rules**

**Example Rules:**

| Rule | Detection |
| --- | --- |
| Sudden spike | Query frequency > threshold |
| Unusual table | Accessing unknown table |
| Large query | Query size too big |
| New pattern | Never-seen-before query |

**Implementation Example**

func detectAnomaly(user string, query string) bool {  
profile := getUserProfile(user)  
  
if len(query) > profile.AvgQuerySize\*3 {  
return true  
}  
  
if !isKnownPattern(profile, query) {  
return true  
}  
  
return false  
}

**7.7 Data Exfiltration Detection**

**Goal: Detect large or suspicious data extraction**

**7.7.1 Detection Indicators**

| Pattern | Risk |
| --- | --- |
| SELECT * | Data dump |
| No LIMIT | Full table scan |
| Large result size | Bulk export |
| Sensitive tables | passwords, tokens |

**7.7.2 Sensitive Table List**

var sensitiveTables = \[\]string{  
"users",  
"passwords",  
"tokens",  
}

**7.7.3 Detection Logic**

func detectExfiltration(ast \*QueryAST) bool {  
for \_, table := range ast.Tables {  
if contains(sensitiveTables, table.Name) {  
if ast.Limit == nil {  
return true  
}  
}  
}  
return false  
}

**7.7.4 Result Size Monitoring**

if rowsReturned > threshold {  
flag = true  
}

**7.8 Decision Engine**

**Combine all signals:**

type Decision struct {  
Block bool  
Flag bool  
Reason string  
}

**Decision Logic:**

func (e \*SecurityEngine) Analyze(query string) Decision {  
if detectInjection(query) {  
return Decision{Block: true, Reason: "SQL Injection"}  
}  
  
if detectExfiltration(ast) {  
return Decision{Flag: true, Reason: "Data Exfiltration"}  
}  
  
if detectAnomaly(user, query) {  
return Decision{Flag: true, Reason: "Anomaly"}  
}  
  
return Decision{}  
}

**7.9 Logging & Alerting**

**Log Structure:**

type SecurityLog struct {  
Query string  
Timestamp time.Time  
Decision string  
Reason string  
}

**Storage:**

*   File (MVP)
*   Database (later)
*   Prometheus (metrics)

**Alerting (Advanced):**

*   Slack webhook
*   Email alerts

**7.10 Performance Constraints**

**Requirements:**

*   Must add **< 5ms overhead**
*   Must not block normal queries unnecessarily

**Optimizations:**

*   Precompile patterns
*   Cache AST
*   Use lightweight checks

**7.11 Testing Strategy**

**Unit Tests:**

*   Injection detection
*   Anomaly detection
*   Exfiltration detection

**Test Cases:**

SELECT \* FROM users WHERE id = 1 OR 1=1

→ BLOCK

SELECT \* FROM users

→ FLAG

**Integration Tests:**

*   Run with real DB queries
*   Ensure no false positives

**7.12 Folder Structure**

security/  
├── engine.go  
├── injection.go  
├── anomaly.go  
├── exfiltration.go  
├── decision.go  
├── middleware.go  
├── logs.go  
└── config.go

**7.13 Deliverables of This Phase**

By end:

✅ SQL injection detection working  
✅ Anomaly detection implemented  
✅ Data exfiltration detection working  
✅ Decision engine integrated  
✅ Middleware connected to API  
✅ Logging system implemented

**7.14 Definition of Done (STRICT)**

You are DONE when:

db.Query(ctx, "SELECT \* FROM users WHERE id = 1 OR 1=1")

❌ Query is BLOCKED

AND:

db.Query(ctx, "SELECT \* FROM users")

⚠️ Query is FLAGGED

**7.15 Common Pitfalls**

❌ Too many false positives  
❌ Blocking legitimate queries  
❌ Slow detection logic  
❌ Ignoring AST-based analysis  
❌ No logging

**7.16 Pro Tips**

*   Start rule-based → then improve
*   Log everything (helps ML later)
*   Make detection configurable
*   Keep engine modular

**7.17 Future Enhancements (VERY POWERFUL)**

*   ML-based anomaly detection
*   Query fingerprinting
*   User behavior modeling
*   Real-time threat scoring

**8\. Connection Management & Performance Optimization (UniDB-Go)**

Implement **adaptive connection pooling, caching strategies, and performance monitoring** to make your system fast, scalable, and observable.

This phase turns your system from “working” → **high-performance middleware**.

**8.1 Objective of This Phase**

Build a performance layer that:

*   Efficiently manages DB connections under high concurrency
*   Reduces latency using intelligent caching
*   Provides deep visibility into system performance

👉 Output: A **high-throughput, low-latency, observable system**

**8.2 High-Level Architecture**

Application  
↓  
API Layer  
↓  
Performance Layer  
├── Connection Pool Manager  
├── Cache Engine  
├── Metrics & Monitoring  
↓  
Execution Engine  
↓  
Databases

**8.3 Connection Management**

**8.3.1 Goals of Connection Pooling**

*   Reuse DB connections (avoid reconnect cost)
*   Support high concurrency (goroutines)
*   Prevent DB overload
*   Dynamically adapt to workload

**8.4 Connection Pool Design**

**8.4.1 Core Structure**

type ConnectionPool struct {  
mu sync.Mutex  
connections chan Connection  
maxSize int  
active int  
}

**8.4.2 Acquire Connection**

func (p \*ConnectionPool) Acquire() (Connection, error) {  
select {  
case conn := <-p.connections:  
return conn, nil  
default:  
if p.active < p.maxSize {  
conn := createNewConnection()  
p.active++  
return conn, nil  
}  
return nil, ErrPoolExhausted  
}  
}

**8.4.3 Release Connection**

func (p \*ConnectionPool) Release(conn Connection) {  
p.connections <- conn  
}

**8.5 Adaptive Connection Pooling (CORE FEATURE)**

**8.5.1 Why Adaptive?**

Static pool size:  
❌ wastes resources  
❌ fails under load

**8.5.2 Metrics to Monitor**

type PoolMetrics struct {  
ActiveConnections int  
IdleConnections int  
WaitTime time.Duration  
ErrorRate float64  
}

**8.5.3 Adaptive Algorithm**

**Increase Pool Size:**

if waitTime > threshold {  
pool.maxSize += 5  
}

**Decrease Pool Size:**

if idleConnections > threshold {  
pool.maxSize -= 2  
}

**8.5.4 Background Auto-Tuner**

func (p \*ConnectionPool) AutoTune() {  
for {  
metrics := p.collectMetrics()  
adjustPool(metrics)  
time.Sleep(5 \* time.Second)  
}  
}

**8.6 Multi-Database Pooling**

**Maintain separate pools per DB:**

type PoolManager struct {  
pools map\[string\]\*ConnectionPool  
}

**Example:**

pools\["postgres"\]  
pools\["mysql"\]  
pools\["mongodb"\]

**8.7 Caching Strategies**

**8.7.1 Why Caching?**

*   Reduce DB calls
*   Improve latency
*   Reduce load

**8.7.2 Cache Types**

**1\. Query Result Cache (PRIMARY)**

type CacheEntry struct {  
Result \[\]Row  
ExpiresAt time.Time  
}

**2\. Execution Plan Cache**

Already built in Phase 5

**3\. Metadata Cache**

*   Table schemas
*   DB capabilities

**8.8 Query Result Caching**

**8.8.1 Cache Key**

key := hash(query + fmt.Sprint(args))

**8.8.2 Cache Lookup**

if val, ok := cache\[key\]; ok && !expired(val) {  
return val.Result  
}

**8.8.3 Cache Storage**

var cache = map\[string\]CacheEntry{}

**8.8.4 Cache Write**

cache\[key\] = CacheEntry{  
Result: rows,  
ExpiresAt: time.Now().Add(1 \* time.Minute),  
}

**8.9 Cache Invalidation (IMPORTANT)**

**When to Invalidate:**

*   INSERT
*   UPDATE
*   DELETE

**Strategy:**

**Simple (MVP):**

Clear entire cache

**Better:**

Tag-based invalidation:

cache\["users:\*"\]

**8.10 Advanced Caching (Optional)**

**LRU Cache**

Use:

*   container/list (Go stdlib)

**Distributed Cache (Future)**

*   Redis integration

**8.11 Performance Monitoring**

**8.11.1 Metrics to Track**

**Query Metrics**

type QueryMetrics struct {  
Latency time.Duration  
QueryType string  
DB string  
}

**System Metrics**

*   Throughput (queries/sec)
*   Error rate
*   Pool utilization

**8.11.2 Metrics Collection**

**Middleware Approach:**

func MetricsMiddleware(next Handler) Handler {  
return func(ctx context.Context, query string, args ...any) (Result, error) {  
start := time.Now()  
res, err := next(ctx, query, args...)  
duration := time.Since(start)  
  
recordMetrics(query, duration, err)  
  
return res, err  
}  
}

**8.12 Observability Stack**

**Recommended Tools:**

*   **Prometheus** → metrics collection
*   **Grafana** → dashboards

**Example Metrics:**

unidb\_query\_latency\_seconds  
unidb\_query\_count  
unidb\_errors\_total  
unidb\_pool\_active\_connections

**8.13 Slow Query Detection**

**Detect:**

if duration > 500\*time.Millisecond {  
logSlowQuery(query)  
}

**8.14 Circuit Breaker (Advanced Resilience)**

**Problem:**

DB becomes slow/unavailable

**Solution:**

if errorRate > threshold {  
openCircuit(db)  
}

**8.15 Load Balancing Across DB Instances**

**Strategy:**

*   Round-robin
*   Least latency
*   Least load

**8.16 Integration with System**

| Component | Role |
| --- | --- |
| API Layer | entry point |
| Pool Manager | connection handling |
| Cache Engine | result caching |
| Metrics Middleware | monitoring |

**8.17 Folder Structure**

performance/  
├── pool/  
│ ├── pool.go  
│ ├── manager.go  
│ ├── autotune.go  
│  
├── cache/  
│ ├── cache.go  
│ ├── lru.go  
│ ├── invalidation.go  
│  
├── metrics/  
│ ├── metrics.go  
│ ├── middleware.go  
│ ├── exporter.go  
│  
└── circuit/  
├── breaker.go

**8.18 Testing Strategy**

**Unit Tests:**

*   Pool acquire/release
*   Cache hit/miss
*   Metrics recording

**Load Testing:**

*   Simulate 1000+ concurrent queries
*   Measure latency

**Tools:**

*   go test -bench
*   wrk / k6

**8.19 Deliverables of This Phase**

By end:

✅ Adaptive connection pooling working  
✅ Multi-DB pool manager  
✅ Query caching implemented  
✅ Cache invalidation working  
✅ Metrics collection integrated  
✅ Prometheus + Grafana support  
✅ Slow query detection

**8.20 Definition of Done (STRICT)**

You are DONE when:

*   System handles **100+ concurrent queries smoothly**
*   Repeated queries are served from cache
*   Pool auto-adjusts under load
*   Metrics visible in dashboard

**8.21 Common Pitfalls**

❌ Memory leaks in connection pool  
❌ Stale cache data  
❌ Over-aggressive caching  
❌ Ignoring monitoring  
❌ Blocking operations in middleware