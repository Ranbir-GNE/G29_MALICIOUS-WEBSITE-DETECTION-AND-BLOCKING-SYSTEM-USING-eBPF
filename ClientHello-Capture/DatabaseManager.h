// DatabaseManager.h
#pragma once
#ifndef DATABASEMANAGER_H
#define DATABASEMANAGER_H

#include <cppconn/driver.h>
#include <cppconn/connection.h>
#include <cppconn/statement.h>
#include <cppconn/resultset.h>
#include <cppconn/exception.h>
#include <iostream>
#include <string>
using namespace std;

class DatabaseManager {
public:
    // Constructor
    DatabaseManager(const string& host, const string& user, const string& password, const string& dbname);

    // Destructor
    ~DatabaseManager();

    // Method to execute a query
    void executeQuery(const string& query);

private:
    sql::Driver *driver;
    sql::Connection *con;
    string host;
    string user;
    string password;
    string dbname;
};


#endif // DATABASEMANAGER_H
