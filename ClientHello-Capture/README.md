# Description

This application allows you to

    - Find out what https websites are being accessed in the network
    - See how much data they consume
    - Store the data usage for upload/download in mysql

# Prerequisits 

For compilation you need to install these:

    sudo apt install libmysqlcppconn-dev libpcap-dev build-essential make g++

Mysql needs to be installed, and it must have the following table:

```sql
CREATE TABLE `bytes_usage` (
  `source_ip` varchar(20) NOT NULL,
  `hostname` text NOT NULL,
  `downloaded` int(11) NOT NULL,
  `uploaded` int(11) NOT NULL,
  `date` DATE NOT NULL DEFAULT (CURDATE()),
  UNIQUE KEY `unique_source_hostname` (`source_ip`,`hostname`) USING HASH
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

# Databse credentials

Db credentials are defined in PacketProcessor.cpp, at the top like this:

```cpp
DatabaseManager db_manager("tcp://127.0.0.1:3306", "root", "Nebero123", "test");
```

db_manager("tcp://127.0.0.1:3306", "username", "password", "database name");


# Compilation

To compile the program, first clean the build directory using make clean, then type make


```bash
make clean
make
```

The main file is in build/packet_analyzer, which is simply run to show the logs and store them in db
