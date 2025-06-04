# Compiler and flags
CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17
LDFLAGS = -lpcap -lmysqlcppconn

# Directories
BUILD_DIR = build
SRC_DIR = .
INCLUDE_DIRS = /usr/include/mysql
LIB_DIRS = /usr/lib/*-linux-gnu
# Source files
SRCS = $(wildcard $(SRC_DIR)/*.cpp)

# Object files
OBJS = $(SRCS:$(SRC_DIR)/%.cpp=$(BUILD_DIR)/%.o)

# Executable name
TARGET = $(BUILD_DIR)/packet_analyzer

# Default target
all: $(TARGET)

# Rule to build the executable
$(TARGET): $(OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LDFLAGS)

# Rule to build object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Rule to clean up
clean:
	rm -rf $(BUILD_DIR)

# Phony targets
.PHONY: all clean
