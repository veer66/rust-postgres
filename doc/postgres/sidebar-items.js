initSidebarItems({"mod":[["types","Traits dealing with Postgres data types"]],"fn":[["cancel_query","Attempts to cancel an in-progress query."]],"enum":[["ConnectError","Reasons a new Postgres connection could fail"],["ConnectTarget","Specifies the target server to connect to."],["Error","An error encountered when communicating with the Postgres server"],["ErrorPosition","Represents the position of an error in a query"],["Kind","Represents the kind of a Postgres type."],["SqlState","SQLSTATE error codes"],["SslMode","Specifies the SSL support requested for a new connection"],["Type","A Postgres type"]],"trait":[["FromSql","A trait for types that can be created from a Postgres value."],["GenericConnection","A trait allowing abstraction over connections and transactions"],["HandleNotice","Trait for types that can handle Postgres notice messages"],["IntoConnectParams","A trait implemented by types that can be converted into a `ConnectParams`."],["RowIndex","A trait implemented by types that can index into columns of a row."],["StreamIterator","An `Iterator` variant which returns borrowed values."],["ToSql","A trait for types that can be converted into Postgres values."]],"struct":[["CancelData","Contains information necessary to cancel queries for a session"],["Column","Information about a column of the result of a query."],["ConnectParams","Information necessary to open a new connection to a Postgres server."],["Connection","A connection to a Postgres database."],["CopyInStatement","A prepared COPY FROM STDIN statement"],["DbError","A Postgres error or notice."],["LazyRows","A lazily-loaded iterator over the resulting rows of a query"],["LoggingNoticeHandler","A notice handler which logs at the `info` level."],["Notification","An asynchronous notification"],["Notifications","An iterator over asynchronous notifications"],["Row","A single result row of a query."],["Rows","The resulting rows of a query."],["RowsIntoIter","An owning iterator over `Row`s."],["RowsIter","An iterator over `Row`s."],["Slice","An adapter type mapping slices to Postgres arrays."],["Statement","A prepared statement"],["Transaction","Represents a transaction on a database connection."],["UserInfo","Authentication information."],["VecStreamIterator","An adapter type implementing `StreamIterator` for a `Vec<Box<ToSql>>`."]],"macro":[["accepts!","Generates a simple implementation of `ToSql::accepts` which accepts the types passed to it."],["to_sql_checked!","Generates an implementation of `ToSql::to_sql_checked`."]],"type":[["Oid","A Postgres OID"],["Result","A type alias of the result returned by many methods."]]});