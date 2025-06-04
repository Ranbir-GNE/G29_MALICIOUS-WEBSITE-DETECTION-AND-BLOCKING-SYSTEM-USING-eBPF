// DatabaseManager.cpp

#include "DatabaseManager.h"

DatabaseManager::DatabaseManager(const string& host, const string& user, const string& password, const string& dbname)
: host(host), user(user), password(password), dbname(dbname) {
    try {
        driver = get_driver_instance();
        con = driver->connect(host, user, password);
        con->setSchema(dbname);
    } catch (sql::SQLException &e) {
        cerr << "# ERR: SQLException in " << __FILE__;
        cerr << "(" << __FUNCTION__ << ") on line " << __LINE__ << endl;
        cerr << "# ERR: " << e.what();
        cerr << " (MySQL error code: " << e.getErrorCode();
        cerr << ", SQLState: " << e.getSQLState() << " )" << endl;
        throw; // rethrow to handle it at a higher level if needed
    }
}

DatabaseManager::~DatabaseManager() {
    if (con) {
        delete con;
    }
}

void DatabaseManager::executeQuery(const string& query) {
    try {
        // std::cout<< query << std::endl;
        sql::Statement *stmt = con->createStatement();
        sql::ResultSet *res = stmt->executeQuery(query);

        // while (res->next()) {
        //     // Print all column data
        //     for (int i = 1; i <= res->getMetaData()->getColumnCount(); ++i) {
        //         cout << res->getString(i) << " ";
        //     }
        //     cout << endl;
        // }

        delete res;
        delete stmt;
    } catch (sql::SQLException &e) {
        ;
        cerr << "# ERR: SQLException in " << __FILE__;
        cerr << "(" << __FUNCTION__ << ") on line " << __LINE__ << endl;
        cerr << "# ERR: " << e.what();
        cerr << " (MySQL error code: " << e.getErrorCode();
        cerr << ", SQLState: " << e.getSQLState() << " )" << endl;
    }
}
