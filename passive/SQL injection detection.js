// Made by kurobeats@yahoo.co.jp, regex shamelessly ripped from SQLMap project errors

const ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100020
name: Information Disclosure - SQL Error
description: An SQL error was found in the HTTP response body.
solution: >
  Ensure proper sanitisation is done on the server side.
risk: high
confidence: medium
cweId: 209  # CWE-209: Generation of Error Message Containing Sensitive Information
wascId: 13  # WASC-13: Information Leakage
status: alpha
codeLink: https://github.com/zaproxy/community-scripts/blob/main/passive/SQL%20injection%20detection.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/community-scripts/
`);
}

function scan(helper, msg, src) {
  const mysql =
    /(SQL syntax.*MySQL|Warning.*mysql_.*|MySqlException \(0x|valid MySQL result|check the manual that corresponds to your (MySQL|MariaDB) server version|MySqlClient\.|com\.mysql\.jdbc\.exceptions)/g;
  const postgresql =
    /(PostgreSQL.*ERROR|Warning.*\Wpg_.*|valid PostgreSQL result|Npgsql\.|PG::SyntaxError:|org\.postgresql\.util\.PSQLException|ERROR:\s\ssyntax error at or near)/g;
  const mssql =
    /(Driver.* SQL[\-\_\ ]*Server|OLE DB.* SQL Server|\bSQL Server.*Driver|Warning.*mssql_.*|\bSQL Server.*[0-9a-fA-F]{8}|[\s\S]Exception.*\WSystem\.Data\.SqlClient\.|[\s\S]Exception.*\WRoadhouse\.Cms\.|Microsoft SQL Native Client.*[0-9a-fA-F]{8})/g;
  const msaccess =
    /(Microsoft Access (\d+ )?Driver|JET Database Engine|Access Database Engine|ODBC Microsoft Access)/g;
  const oracle =
    /(\bORA-\d{5}|Oracle error|Oracle.*Driver|Warning.*\Woci_.*|Warning.*\Wora_.*)/g;
  const ibmdb2 =
    /(CLI Driver.*DB2|DB2 SQL error|\bdb2_\w+\(|SQLSTATE.+SQLCODE)/g;
  const informix = /(Exception.*Informix)/g;
  const firebird = /(Dynamic SQL Error|Warning.*ibase_.*)/g;
  const sqlite =
    /(SQLite\/JDBCDriver|SQLite.Exception|System.Data.SQLite.SQLiteException|Warning.*sqlite_.*|Warning.*SQLite3::|\[SQLITE_ERROR\])/g;
  const sapdb = /(SQL error.*POS([0-9]+).*|Warning.*maxdb.*)/g;
  const sybase =
    /(Warning.*sybase.*|Sybase message|Sybase.*Server message.*|SybSQLException|com\.sybase\.jdbc)/g;
  const ingress = /(Warning.*ingres_|Ingres SQLSTATE|Ingres\W.*Driver)/g;
  const frontbase = /(Exception (condition )?\d+. Transaction rollback.)/g;
  const hsqldb =
    /(org\.hsqldb\.jdbc|Unexpected end of command in statement \[|Unexpected token.*in statement \[)/g;

  const sqlImplementations = [
    { name: "MySQL", regex: mysql },
    { name: "PostgreSQL", regex: postgresql },
    { name: "MSSQL", regex: mssql },
    { name: "Microsoft Access", regex: msaccess },
    { name: "Oracle", regex: oracle },
    { name: "IBM DB2", regex: ibmdb2 },
    { name: "Informix", regex: informix },
    { name: "Firebird", regex: firebird },
    { name: "SQLite", regex: sqlite },
    { name: "SAP DB", regex: sapdb },
    { name: "Sybase", regex: sybase },
    { name: "Ingress", regex: ingress },
    { name: "Frontbase", regex: frontbase },
    { name: "HSQLDB", regex: hsqldb },
  ];

  const body = msg.getResponseBody().toString();
  for (let i = 0; i < sqlImplementations.length; i++) {
    const sqlImpl = sqlImplementations[i];
    const alertTitle = `Information Disclosure - ${sqlImpl.name} error`;
    const article = sqlImpl.name.match(/^(?:[IO]|MS|SQ|H)/) ? "An" : "A";
    const alertDesc = `${article} ${sqlImpl.name} error was discovered in the HTTP response body.`;
    if (sqlImpl.regex.test(body)) {
      sqlImpl.regex.lastIndex = 0;
      const found = [];
      let sqlError;
      while ((sqlError = sqlImpl.regex.exec(body))) {
        found.push(sqlError[0]);
      }
      const otherInfo =
        found.length > 1 ? `Other instances: ${found.slice(1).toString()}` : "";
      helper
        .newAlert()
        .setName(alertTitle)
        .setDescription(alertDesc)
        .setEvidence(found[0])
        .setOtherInfo(otherInfo)
        .setMessage(msg)
        .raise();
    }
  }
}
