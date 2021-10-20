# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Default target executed when no arguments are given to make.
default_target: all

.PHONY : default_target

# Allow only one "make -f Makefile2" at a time, but pass parallelism.
.NOTPARALLEL:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/b/Downloads/2021-anp-netstack-framework-04dcdde

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/b/Downloads/2021-anp-netstack-framework-04dcdde

#=============================================================================
# Targets provided globally by CMake.

# Special rule for the target install/local
install/local: preinstall
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Installing only the local directory..."
	/usr/bin/cmake -DCMAKE_INSTALL_LOCAL_ONLY=1 -P cmake_install.cmake
.PHONY : install/local

# Special rule for the target install/local
install/local/fast: preinstall/fast
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Installing only the local directory..."
	/usr/bin/cmake -DCMAKE_INSTALL_LOCAL_ONLY=1 -P cmake_install.cmake
.PHONY : install/local/fast

# Special rule for the target install/strip
install/strip: preinstall
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Installing the project stripped..."
	/usr/bin/cmake -DCMAKE_INSTALL_DO_STRIP=1 -P cmake_install.cmake
.PHONY : install/strip

# Special rule for the target install/strip
install/strip/fast: preinstall/fast
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Installing the project stripped..."
	/usr/bin/cmake -DCMAKE_INSTALL_DO_STRIP=1 -P cmake_install.cmake
.PHONY : install/strip/fast

# Special rule for the target list_install_components
list_install_components:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Available install components are: \"Unspecified\""
.PHONY : list_install_components

# Special rule for the target list_install_components
list_install_components/fast: list_install_components

.PHONY : list_install_components/fast

# Special rule for the target rebuild_cache
rebuild_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake to regenerate build system..."
	/usr/bin/cmake -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : rebuild_cache

# Special rule for the target rebuild_cache
rebuild_cache/fast: rebuild_cache

.PHONY : rebuild_cache/fast

# Special rule for the target install
install: preinstall
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Install the project..."
	/usr/bin/cmake -P cmake_install.cmake
.PHONY : install

# Special rule for the target install
install/fast: preinstall/fast
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Install the project..."
	/usr/bin/cmake -P cmake_install.cmake
.PHONY : install/fast

# Special rule for the target edit_cache
edit_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "No interactive CMake dialog available..."
	/usr/bin/cmake -E echo No\ interactive\ CMake\ dialog\ available.
.PHONY : edit_cache

# Special rule for the target edit_cache
edit_cache/fast: edit_cache

.PHONY : edit_cache/fast

# The main all target
all: cmake_check_build_system
	$(CMAKE_COMMAND) -E cmake_progress_start /home/b/Downloads/2021-anp-netstack-framework-04dcdde/CMakeFiles /home/b/Downloads/2021-anp-netstack-framework-04dcdde/CMakeFiles/progress.marks
	$(MAKE) -f CMakeFiles/Makefile2 all
	$(CMAKE_COMMAND) -E cmake_progress_start /home/b/Downloads/2021-anp-netstack-framework-04dcdde/CMakeFiles 0
.PHONY : all

# The main clean target
clean:
	$(MAKE) -f CMakeFiles/Makefile2 clean
.PHONY : clean

# The main clean target
clean/fast: clean

.PHONY : clean/fast

# Prepare targets for installation.
preinstall: all
	$(MAKE) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall

# Prepare targets for installation.
preinstall/fast:
	$(MAKE) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall/fast

# clear depends
depend:
	$(CMAKE_COMMAND) -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 1
.PHONY : depend

#=============================================================================
# Target rules for targets named anp_server

# Build rule for target.
anp_server: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 anp_server
.PHONY : anp_server

# fast build rule for target.
anp_server/fast:
	$(MAKE) -f CMakeFiles/anp_server.dir/build.make CMakeFiles/anp_server.dir/build
.PHONY : anp_server/fast

#=============================================================================
# Target rules for targets named anpnetstack

# Build rule for target.
anpnetstack: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 anpnetstack
.PHONY : anpnetstack

# fast build rule for target.
anpnetstack/fast:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/build
.PHONY : anpnetstack/fast

#=============================================================================
# Target rules for targets named anp_client

# Build rule for target.
anp_client: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 anp_client
.PHONY : anp_client

# fast build rule for target.
anp_client/fast:
	$(MAKE) -f CMakeFiles/anp_client.dir/build.make CMakeFiles/anp_client.dir/build
.PHONY : anp_client/fast

server-client/common.o: server-client/common.c.o

.PHONY : server-client/common.o

# target to build an object file
server-client/common.c.o:
	$(MAKE) -f CMakeFiles/anp_server.dir/build.make CMakeFiles/anp_server.dir/server-client/common.c.o
	$(MAKE) -f CMakeFiles/anp_client.dir/build.make CMakeFiles/anp_client.dir/server-client/common.c.o
.PHONY : server-client/common.c.o

server-client/common.i: server-client/common.c.i

.PHONY : server-client/common.i

# target to preprocess a source file
server-client/common.c.i:
	$(MAKE) -f CMakeFiles/anp_server.dir/build.make CMakeFiles/anp_server.dir/server-client/common.c.i
	$(MAKE) -f CMakeFiles/anp_client.dir/build.make CMakeFiles/anp_client.dir/server-client/common.c.i
.PHONY : server-client/common.c.i

server-client/common.s: server-client/common.c.s

.PHONY : server-client/common.s

# target to generate assembly for a file
server-client/common.c.s:
	$(MAKE) -f CMakeFiles/anp_server.dir/build.make CMakeFiles/anp_server.dir/server-client/common.c.s
	$(MAKE) -f CMakeFiles/anp_client.dir/build.make CMakeFiles/anp_client.dir/server-client/common.c.s
.PHONY : server-client/common.c.s

server-client/tcp_client.o: server-client/tcp_client.c.o

.PHONY : server-client/tcp_client.o

# target to build an object file
server-client/tcp_client.c.o:
	$(MAKE) -f CMakeFiles/anp_client.dir/build.make CMakeFiles/anp_client.dir/server-client/tcp_client.c.o
.PHONY : server-client/tcp_client.c.o

server-client/tcp_client.i: server-client/tcp_client.c.i

.PHONY : server-client/tcp_client.i

# target to preprocess a source file
server-client/tcp_client.c.i:
	$(MAKE) -f CMakeFiles/anp_client.dir/build.make CMakeFiles/anp_client.dir/server-client/tcp_client.c.i
.PHONY : server-client/tcp_client.c.i

server-client/tcp_client.s: server-client/tcp_client.c.s

.PHONY : server-client/tcp_client.s

# target to generate assembly for a file
server-client/tcp_client.c.s:
	$(MAKE) -f CMakeFiles/anp_client.dir/build.make CMakeFiles/anp_client.dir/server-client/tcp_client.c.s
.PHONY : server-client/tcp_client.c.s

server-client/tcp_server.o: server-client/tcp_server.c.o

.PHONY : server-client/tcp_server.o

# target to build an object file
server-client/tcp_server.c.o:
	$(MAKE) -f CMakeFiles/anp_server.dir/build.make CMakeFiles/anp_server.dir/server-client/tcp_server.c.o
.PHONY : server-client/tcp_server.c.o

server-client/tcp_server.i: server-client/tcp_server.c.i

.PHONY : server-client/tcp_server.i

# target to preprocess a source file
server-client/tcp_server.c.i:
	$(MAKE) -f CMakeFiles/anp_server.dir/build.make CMakeFiles/anp_server.dir/server-client/tcp_server.c.i
.PHONY : server-client/tcp_server.c.i

server-client/tcp_server.s: server-client/tcp_server.c.s

.PHONY : server-client/tcp_server.s

# target to generate assembly for a file
server-client/tcp_server.c.s:
	$(MAKE) -f CMakeFiles/anp_server.dir/build.make CMakeFiles/anp_server.dir/server-client/tcp_server.c.s
.PHONY : server-client/tcp_server.c.s

src/anp_netdev.o: src/anp_netdev.c.o

.PHONY : src/anp_netdev.o

# target to build an object file
src/anp_netdev.c.o:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/anp_netdev.c.o
.PHONY : src/anp_netdev.c.o

src/anp_netdev.i: src/anp_netdev.c.i

.PHONY : src/anp_netdev.i

# target to preprocess a source file
src/anp_netdev.c.i:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/anp_netdev.c.i
.PHONY : src/anp_netdev.c.i

src/anp_netdev.s: src/anp_netdev.c.s

.PHONY : src/anp_netdev.s

# target to generate assembly for a file
src/anp_netdev.c.s:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/anp_netdev.c.s
.PHONY : src/anp_netdev.c.s

src/anpwrapper.o: src/anpwrapper.c.o

.PHONY : src/anpwrapper.o

# target to build an object file
src/anpwrapper.c.o:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/anpwrapper.c.o
.PHONY : src/anpwrapper.c.o

src/anpwrapper.i: src/anpwrapper.c.i

.PHONY : src/anpwrapper.i

# target to preprocess a source file
src/anpwrapper.c.i:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/anpwrapper.c.i
.PHONY : src/anpwrapper.c.i

src/anpwrapper.s: src/anpwrapper.c.s

.PHONY : src/anpwrapper.s

# target to generate assembly for a file
src/anpwrapper.c.s:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/anpwrapper.c.s
.PHONY : src/anpwrapper.c.s

src/arp.o: src/arp.c.o

.PHONY : src/arp.o

# target to build an object file
src/arp.c.o:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/arp.c.o
.PHONY : src/arp.c.o

src/arp.i: src/arp.c.i

.PHONY : src/arp.i

# target to preprocess a source file
src/arp.c.i:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/arp.c.i
.PHONY : src/arp.c.i

src/arp.s: src/arp.c.s

.PHONY : src/arp.s

# target to generate assembly for a file
src/arp.c.s:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/arp.c.s
.PHONY : src/arp.c.s

src/icmp.o: src/icmp.c.o

.PHONY : src/icmp.o

# target to build an object file
src/icmp.c.o:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/icmp.c.o
.PHONY : src/icmp.c.o

src/icmp.i: src/icmp.c.i

.PHONY : src/icmp.i

# target to preprocess a source file
src/icmp.c.i:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/icmp.c.i
.PHONY : src/icmp.c.i

src/icmp.s: src/icmp.c.s

.PHONY : src/icmp.s

# target to generate assembly for a file
src/icmp.c.s:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/icmp.c.s
.PHONY : src/icmp.c.s

src/init.o: src/init.c.o

.PHONY : src/init.o

# target to build an object file
src/init.c.o:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/init.c.o
.PHONY : src/init.c.o

src/init.i: src/init.c.i

.PHONY : src/init.i

# target to preprocess a source file
src/init.c.i:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/init.c.i
.PHONY : src/init.c.i

src/init.s: src/init.c.s

.PHONY : src/init.s

# target to generate assembly for a file
src/init.c.s:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/init.c.s
.PHONY : src/init.c.s

src/ip_rx.o: src/ip_rx.c.o

.PHONY : src/ip_rx.o

# target to build an object file
src/ip_rx.c.o:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/ip_rx.c.o
.PHONY : src/ip_rx.c.o

src/ip_rx.i: src/ip_rx.c.i

.PHONY : src/ip_rx.i

# target to preprocess a source file
src/ip_rx.c.i:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/ip_rx.c.i
.PHONY : src/ip_rx.c.i

src/ip_rx.s: src/ip_rx.c.s

.PHONY : src/ip_rx.s

# target to generate assembly for a file
src/ip_rx.c.s:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/ip_rx.c.s
.PHONY : src/ip_rx.c.s

src/ip_tx.o: src/ip_tx.c.o

.PHONY : src/ip_tx.o

# target to build an object file
src/ip_tx.c.o:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/ip_tx.c.o
.PHONY : src/ip_tx.c.o

src/ip_tx.i: src/ip_tx.c.i

.PHONY : src/ip_tx.i

# target to preprocess a source file
src/ip_tx.c.i:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/ip_tx.c.i
.PHONY : src/ip_tx.c.i

src/ip_tx.s: src/ip_tx.c.s

.PHONY : src/ip_tx.s

# target to generate assembly for a file
src/ip_tx.c.s:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/ip_tx.c.s
.PHONY : src/ip_tx.c.s

src/queue.o: src/queue.c.o

.PHONY : src/queue.o

# target to build an object file
src/queue.c.o:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/queue.c.o
.PHONY : src/queue.c.o

src/queue.i: src/queue.c.i

.PHONY : src/queue.i

# target to preprocess a source file
src/queue.c.i:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/queue.c.i
.PHONY : src/queue.c.i

src/queue.s: src/queue.c.s

.PHONY : src/queue.s

# target to generate assembly for a file
src/queue.c.s:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/queue.c.s
.PHONY : src/queue.c.s

src/route.o: src/route.c.o

.PHONY : src/route.o

# target to build an object file
src/route.c.o:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/route.c.o
.PHONY : src/route.c.o

src/route.i: src/route.c.i

.PHONY : src/route.i

# target to preprocess a source file
src/route.c.i:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/route.c.i
.PHONY : src/route.c.i

src/route.s: src/route.c.s

.PHONY : src/route.s

# target to generate assembly for a file
src/route.c.s:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/route.c.s
.PHONY : src/route.c.s

src/sock.o: src/sock.c.o

.PHONY : src/sock.o

# target to build an object file
src/sock.c.o:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/sock.c.o
.PHONY : src/sock.c.o

src/sock.i: src/sock.c.i

.PHONY : src/sock.i

# target to preprocess a source file
src/sock.c.i:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/sock.c.i
.PHONY : src/sock.c.i

src/sock.s: src/sock.c.s

.PHONY : src/sock.s

# target to generate assembly for a file
src/sock.c.s:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/sock.c.s
.PHONY : src/sock.c.s

src/subuff.o: src/subuff.c.o

.PHONY : src/subuff.o

# target to build an object file
src/subuff.c.o:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/subuff.c.o
.PHONY : src/subuff.c.o

src/subuff.i: src/subuff.c.i

.PHONY : src/subuff.i

# target to preprocess a source file
src/subuff.c.i:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/subuff.c.i
.PHONY : src/subuff.c.i

src/subuff.s: src/subuff.c.s

.PHONY : src/subuff.s

# target to generate assembly for a file
src/subuff.c.s:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/subuff.c.s
.PHONY : src/subuff.c.s

src/sync.o: src/sync.c.o

.PHONY : src/sync.o

# target to build an object file
src/sync.c.o:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/sync.c.o
.PHONY : src/sync.c.o

src/sync.i: src/sync.c.i

.PHONY : src/sync.i

# target to preprocess a source file
src/sync.c.i:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/sync.c.i
.PHONY : src/sync.c.i

src/sync.s: src/sync.c.s

.PHONY : src/sync.s

# target to generate assembly for a file
src/sync.c.s:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/sync.c.s
.PHONY : src/sync.c.s

src/tap_netdev.o: src/tap_netdev.c.o

.PHONY : src/tap_netdev.o

# target to build an object file
src/tap_netdev.c.o:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/tap_netdev.c.o
.PHONY : src/tap_netdev.c.o

src/tap_netdev.i: src/tap_netdev.c.i

.PHONY : src/tap_netdev.i

# target to preprocess a source file
src/tap_netdev.c.i:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/tap_netdev.c.i
.PHONY : src/tap_netdev.c.i

src/tap_netdev.s: src/tap_netdev.c.s

.PHONY : src/tap_netdev.s

# target to generate assembly for a file
src/tap_netdev.c.s:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/tap_netdev.c.s
.PHONY : src/tap_netdev.c.s

src/tcp.o: src/tcp.c.o

.PHONY : src/tcp.o

# target to build an object file
src/tcp.c.o:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/tcp.c.o
.PHONY : src/tcp.c.o

src/tcp.i: src/tcp.c.i

.PHONY : src/tcp.i

# target to preprocess a source file
src/tcp.c.i:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/tcp.c.i
.PHONY : src/tcp.c.i

src/tcp.s: src/tcp.c.s

.PHONY : src/tcp.s

# target to generate assembly for a file
src/tcp.c.s:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/tcp.c.s
.PHONY : src/tcp.c.s

src/timer.o: src/timer.c.o

.PHONY : src/timer.o

# target to build an object file
src/timer.c.o:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/timer.c.o
.PHONY : src/timer.c.o

src/timer.i: src/timer.c.i

.PHONY : src/timer.i

# target to preprocess a source file
src/timer.c.i:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/timer.c.i
.PHONY : src/timer.c.i

src/timer.s: src/timer.c.s

.PHONY : src/timer.s

# target to generate assembly for a file
src/timer.c.s:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/timer.c.s
.PHONY : src/timer.c.s

src/utilities.o: src/utilities.c.o

.PHONY : src/utilities.o

# target to build an object file
src/utilities.c.o:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/utilities.c.o
.PHONY : src/utilities.c.o

src/utilities.i: src/utilities.c.i

.PHONY : src/utilities.i

# target to preprocess a source file
src/utilities.c.i:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/utilities.c.i
.PHONY : src/utilities.c.i

src/utilities.s: src/utilities.c.s

.PHONY : src/utilities.s

# target to generate assembly for a file
src/utilities.c.s:
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/utilities.c.s
.PHONY : src/utilities.c.s

# Help Target
help:
	@echo "The following are some of the valid targets for this Makefile:"
	@echo "... all (the default if no target is provided)"
	@echo "... clean"
	@echo "... depend"
	@echo "... install/local"
	@echo "... install/strip"
	@echo "... anp_server"
	@echo "... list_install_components"
	@echo "... anpnetstack"
	@echo "... rebuild_cache"
	@echo "... install"
	@echo "... anp_client"
	@echo "... edit_cache"
	@echo "... server-client/common.o"
	@echo "... server-client/common.i"
	@echo "... server-client/common.s"
	@echo "... server-client/tcp_client.o"
	@echo "... server-client/tcp_client.i"
	@echo "... server-client/tcp_client.s"
	@echo "... server-client/tcp_server.o"
	@echo "... server-client/tcp_server.i"
	@echo "... server-client/tcp_server.s"
	@echo "... src/anp_netdev.o"
	@echo "... src/anp_netdev.i"
	@echo "... src/anp_netdev.s"
	@echo "... src/anpwrapper.o"
	@echo "... src/anpwrapper.i"
	@echo "... src/anpwrapper.s"
	@echo "... src/arp.o"
	@echo "... src/arp.i"
	@echo "... src/arp.s"
	@echo "... src/icmp.o"
	@echo "... src/icmp.i"
	@echo "... src/icmp.s"
	@echo "... src/init.o"
	@echo "... src/init.i"
	@echo "... src/init.s"
	@echo "... src/ip_rx.o"
	@echo "... src/ip_rx.i"
	@echo "... src/ip_rx.s"
	@echo "... src/ip_tx.o"
	@echo "... src/ip_tx.i"
	@echo "... src/ip_tx.s"
	@echo "... src/queue.o"
	@echo "... src/queue.i"
	@echo "... src/queue.s"
	@echo "... src/route.o"
	@echo "... src/route.i"
	@echo "... src/route.s"
	@echo "... src/sock.o"
	@echo "... src/sock.i"
	@echo "... src/sock.s"
	@echo "... src/subuff.o"
	@echo "... src/subuff.i"
	@echo "... src/subuff.s"
	@echo "... src/sync.o"
	@echo "... src/sync.i"
	@echo "... src/sync.s"
	@echo "... src/tap_netdev.o"
	@echo "... src/tap_netdev.i"
	@echo "... src/tap_netdev.s"
	@echo "... src/tcp.o"
	@echo "... src/tcp.i"
	@echo "... src/tcp.s"
	@echo "... src/timer.o"
	@echo "... src/timer.i"
	@echo "... src/timer.s"
	@echo "... src/utilities.o"
	@echo "... src/utilities.i"
	@echo "... src/utilities.s"
.PHONY : help



#=============================================================================
# Special targets to cleanup operation of make.

# Special rule to run CMake to check the build system integrity.
# No rule that depends on this can have commands that come from listfiles
# because they might be regenerated.
cmake_check_build_system:
	$(CMAKE_COMMAND) -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 0
.PHONY : cmake_check_build_system

