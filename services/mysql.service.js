const mysql = require('mysql');

const mysqlService = {
  connection: null,
  init(url, config = {}) {
    this.connection = mysql.createConnection({
        host: process.env.MYSQL_HOST,
        user: process.env.MYSQL_USER,
        password: process.env.MYSQL_PASSWORD,
        database: process.env.MYSQL_DATABASE
    });
  },
  query(query, data = {}, callbackError = null, callbackSuccess = null) {
    this.init();
    const queryObject = this.connection.query(query, data, function (error, results, fields) {
      if (error && callbackError) {
        console.log('MYSQL ERROR: ', error);
        callbackError(error);
      }
      // console.log('The solution is: ', results);
      // console.log('The solution is: ', fields);
      if (callbackSuccess) callbackSuccess(results);
    });
    console.log('queryObject.sql', queryObject.sql);
    return queryObject;
    this.connection.end();
  },
  escape(value) {
    return this.connection.escape(value);
  },
}

module.exports = mysqlService;
