// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

function scan(ps, msg, src)
{
    var url = msg.getRequestHeader().getURI().toString();
    var body = msg.getResponseBody().toString()
    var alertRisk = [0,1,2,3,4] //1=informational, 2=low, 3=medium, 4=high
    var alertConfidence = [0,1,2,3,4] //0=fp,1=low,2=medium,3=high,4=confirmed
    var alertTitle = ["MySQL client command history file Disclosed (script)",
		  "PostgreSQL client command history file Disclosed (script)",
		  "PostgreSQL password file Disclosed (script)",
		  "DBeaver SQL database manager configuration file Disclosed (script)",
		  "SQL dump file Disclosed (script)",
		  ""]
    var alertDesc = ["A MySQL client command history file was discovered.",
		 "A PostgreSQL client command history file was discovered.",
		 "A PostgreSQL password file was discovered.",
		 "DBeaver SQL database manager configuration file was discovered.",
		 "SQL dump file was discovered.",
		""]
    var alertSolution = ["Ensure configuration files, passwords and backups that are stored securely.",
		    ""]
    var cweId = [0,1]
    var wascId = [0,1]

    var mysqlhistory = /((\.)?mysql_history)/g
    var postsqlhistory = /((\.)?psql_history)/g
    var postgrespass = /((\.)?pgpass)/g
    var dbeaverconfig = /\.?dbeaver-data-sources(-[0-9]+)?\.xml/g
    var sqldump = /(\.sql(dump)?)/g

	if (mysqlhistory.test(body))
	  {
	    mysqlhistory.lastIndex = 0
	    var foundmysqlhistory = []
	    var comm
            while (comm = mysqlhistory.exec(body))
	      {
               foundmysqlhistory.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[0], alertDesc[0], url, '', '', foundmysqlhistory.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }

	if (postsqlhistory.test(body))
	  {
	    postsqlhistory.lastIndex = 0
	    var foundpostsqlhistory = []
            while (comm = postsqlhistory.exec(body))
	      {
               foundpostsqlhistory.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[1], alertDesc[1], url, '', '', foundpostsqlhistory.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (postgrespass.test(body))
	  {
	    postgrespass.lastIndex = 0
	    var foundpostgrespass = []
            while (comm = postgrespass.exec(body))
	      {
               foundpostgrespass.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[2], alertDesc[2], url, '', '', foundpostgrespass.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (dbeaverconfig.test(body))
	  {
	    dbeaverconfig.lastIndex = 0
	    var founddbeaverconfig = []
            while (comm = dbeaverconfig.exec(body))
	      {
               founddbeaverconfig.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[3], alertDesc[3], url, '', '', founddbeaverconfig.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }

	if (sqldump.test(body))
	  {
	    sqldump.lastIndex = 0
	    var foundsqldump = []
            while (comm = sqldump.exec(body))
	      {
               foundsqldump.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[4], alertDesc[4], url, '', '', foundsqldump.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
}
