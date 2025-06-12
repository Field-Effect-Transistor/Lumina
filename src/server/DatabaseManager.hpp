//  DatabaseManager.cpp

#pragma once

#include <sqlite3.h>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>

class DatabaseManager {
private:
    sqlite3* db_;
    char* zErrMsg = 0;
    int rc;

public:
    DatabaseManager(const std::string& db_path);
    ~DatabaseManager();

};
