# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


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
CMAKE_SOURCE_DIR = /home/b/Downloads/anp-main

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/b/Downloads/anp-main

# Include any dependencies generated for this target.
include CMakeFiles/anpnetstack.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/anpnetstack.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/anpnetstack.dir/flags.make

CMakeFiles/anpnetstack.dir/src/init.c.o: CMakeFiles/anpnetstack.dir/flags.make
CMakeFiles/anpnetstack.dir/src/init.c.o: src/init.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/b/Downloads/anp-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/anpnetstack.dir/src/init.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/anpnetstack.dir/src/init.c.o   -c /home/b/Downloads/anp-main/src/init.c

CMakeFiles/anpnetstack.dir/src/init.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/anpnetstack.dir/src/init.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/b/Downloads/anp-main/src/init.c > CMakeFiles/anpnetstack.dir/src/init.c.i

CMakeFiles/anpnetstack.dir/src/init.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/anpnetstack.dir/src/init.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/b/Downloads/anp-main/src/init.c -o CMakeFiles/anpnetstack.dir/src/init.c.s

CMakeFiles/anpnetstack.dir/src/init.c.o.requires:

.PHONY : CMakeFiles/anpnetstack.dir/src/init.c.o.requires

CMakeFiles/anpnetstack.dir/src/init.c.o.provides: CMakeFiles/anpnetstack.dir/src/init.c.o.requires
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/init.c.o.provides.build
.PHONY : CMakeFiles/anpnetstack.dir/src/init.c.o.provides

CMakeFiles/anpnetstack.dir/src/init.c.o.provides.build: CMakeFiles/anpnetstack.dir/src/init.c.o


CMakeFiles/anpnetstack.dir/src/tap_netdev.c.o: CMakeFiles/anpnetstack.dir/flags.make
CMakeFiles/anpnetstack.dir/src/tap_netdev.c.o: src/tap_netdev.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/b/Downloads/anp-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/anpnetstack.dir/src/tap_netdev.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/anpnetstack.dir/src/tap_netdev.c.o   -c /home/b/Downloads/anp-main/src/tap_netdev.c

CMakeFiles/anpnetstack.dir/src/tap_netdev.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/anpnetstack.dir/src/tap_netdev.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/b/Downloads/anp-main/src/tap_netdev.c > CMakeFiles/anpnetstack.dir/src/tap_netdev.c.i

CMakeFiles/anpnetstack.dir/src/tap_netdev.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/anpnetstack.dir/src/tap_netdev.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/b/Downloads/anp-main/src/tap_netdev.c -o CMakeFiles/anpnetstack.dir/src/tap_netdev.c.s

CMakeFiles/anpnetstack.dir/src/tap_netdev.c.o.requires:

.PHONY : CMakeFiles/anpnetstack.dir/src/tap_netdev.c.o.requires

CMakeFiles/anpnetstack.dir/src/tap_netdev.c.o.provides: CMakeFiles/anpnetstack.dir/src/tap_netdev.c.o.requires
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/tap_netdev.c.o.provides.build
.PHONY : CMakeFiles/anpnetstack.dir/src/tap_netdev.c.o.provides

CMakeFiles/anpnetstack.dir/src/tap_netdev.c.o.provides.build: CMakeFiles/anpnetstack.dir/src/tap_netdev.c.o


CMakeFiles/anpnetstack.dir/src/utilities.c.o: CMakeFiles/anpnetstack.dir/flags.make
CMakeFiles/anpnetstack.dir/src/utilities.c.o: src/utilities.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/b/Downloads/anp-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/anpnetstack.dir/src/utilities.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/anpnetstack.dir/src/utilities.c.o   -c /home/b/Downloads/anp-main/src/utilities.c

CMakeFiles/anpnetstack.dir/src/utilities.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/anpnetstack.dir/src/utilities.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/b/Downloads/anp-main/src/utilities.c > CMakeFiles/anpnetstack.dir/src/utilities.c.i

CMakeFiles/anpnetstack.dir/src/utilities.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/anpnetstack.dir/src/utilities.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/b/Downloads/anp-main/src/utilities.c -o CMakeFiles/anpnetstack.dir/src/utilities.c.s

CMakeFiles/anpnetstack.dir/src/utilities.c.o.requires:

.PHONY : CMakeFiles/anpnetstack.dir/src/utilities.c.o.requires

CMakeFiles/anpnetstack.dir/src/utilities.c.o.provides: CMakeFiles/anpnetstack.dir/src/utilities.c.o.requires
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/utilities.c.o.provides.build
.PHONY : CMakeFiles/anpnetstack.dir/src/utilities.c.o.provides

CMakeFiles/anpnetstack.dir/src/utilities.c.o.provides.build: CMakeFiles/anpnetstack.dir/src/utilities.c.o


CMakeFiles/anpnetstack.dir/src/anp_netdev.c.o: CMakeFiles/anpnetstack.dir/flags.make
CMakeFiles/anpnetstack.dir/src/anp_netdev.c.o: src/anp_netdev.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/b/Downloads/anp-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/anpnetstack.dir/src/anp_netdev.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/anpnetstack.dir/src/anp_netdev.c.o   -c /home/b/Downloads/anp-main/src/anp_netdev.c

CMakeFiles/anpnetstack.dir/src/anp_netdev.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/anpnetstack.dir/src/anp_netdev.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/b/Downloads/anp-main/src/anp_netdev.c > CMakeFiles/anpnetstack.dir/src/anp_netdev.c.i

CMakeFiles/anpnetstack.dir/src/anp_netdev.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/anpnetstack.dir/src/anp_netdev.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/b/Downloads/anp-main/src/anp_netdev.c -o CMakeFiles/anpnetstack.dir/src/anp_netdev.c.s

CMakeFiles/anpnetstack.dir/src/anp_netdev.c.o.requires:

.PHONY : CMakeFiles/anpnetstack.dir/src/anp_netdev.c.o.requires

CMakeFiles/anpnetstack.dir/src/anp_netdev.c.o.provides: CMakeFiles/anpnetstack.dir/src/anp_netdev.c.o.requires
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/anp_netdev.c.o.provides.build
.PHONY : CMakeFiles/anpnetstack.dir/src/anp_netdev.c.o.provides

CMakeFiles/anpnetstack.dir/src/anp_netdev.c.o.provides.build: CMakeFiles/anpnetstack.dir/src/anp_netdev.c.o


CMakeFiles/anpnetstack.dir/src/anpwrapper.c.o: CMakeFiles/anpnetstack.dir/flags.make
CMakeFiles/anpnetstack.dir/src/anpwrapper.c.o: src/anpwrapper.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/b/Downloads/anp-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/anpnetstack.dir/src/anpwrapper.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/anpnetstack.dir/src/anpwrapper.c.o   -c /home/b/Downloads/anp-main/src/anpwrapper.c

CMakeFiles/anpnetstack.dir/src/anpwrapper.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/anpnetstack.dir/src/anpwrapper.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/b/Downloads/anp-main/src/anpwrapper.c > CMakeFiles/anpnetstack.dir/src/anpwrapper.c.i

CMakeFiles/anpnetstack.dir/src/anpwrapper.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/anpnetstack.dir/src/anpwrapper.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/b/Downloads/anp-main/src/anpwrapper.c -o CMakeFiles/anpnetstack.dir/src/anpwrapper.c.s

CMakeFiles/anpnetstack.dir/src/anpwrapper.c.o.requires:

.PHONY : CMakeFiles/anpnetstack.dir/src/anpwrapper.c.o.requires

CMakeFiles/anpnetstack.dir/src/anpwrapper.c.o.provides: CMakeFiles/anpnetstack.dir/src/anpwrapper.c.o.requires
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/anpwrapper.c.o.provides.build
.PHONY : CMakeFiles/anpnetstack.dir/src/anpwrapper.c.o.provides

CMakeFiles/anpnetstack.dir/src/anpwrapper.c.o.provides.build: CMakeFiles/anpnetstack.dir/src/anpwrapper.c.o


CMakeFiles/anpnetstack.dir/src/arp.c.o: CMakeFiles/anpnetstack.dir/flags.make
CMakeFiles/anpnetstack.dir/src/arp.c.o: src/arp.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/b/Downloads/anp-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building C object CMakeFiles/anpnetstack.dir/src/arp.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/anpnetstack.dir/src/arp.c.o   -c /home/b/Downloads/anp-main/src/arp.c

CMakeFiles/anpnetstack.dir/src/arp.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/anpnetstack.dir/src/arp.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/b/Downloads/anp-main/src/arp.c > CMakeFiles/anpnetstack.dir/src/arp.c.i

CMakeFiles/anpnetstack.dir/src/arp.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/anpnetstack.dir/src/arp.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/b/Downloads/anp-main/src/arp.c -o CMakeFiles/anpnetstack.dir/src/arp.c.s

CMakeFiles/anpnetstack.dir/src/arp.c.o.requires:

.PHONY : CMakeFiles/anpnetstack.dir/src/arp.c.o.requires

CMakeFiles/anpnetstack.dir/src/arp.c.o.provides: CMakeFiles/anpnetstack.dir/src/arp.c.o.requires
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/arp.c.o.provides.build
.PHONY : CMakeFiles/anpnetstack.dir/src/arp.c.o.provides

CMakeFiles/anpnetstack.dir/src/arp.c.o.provides.build: CMakeFiles/anpnetstack.dir/src/arp.c.o


CMakeFiles/anpnetstack.dir/src/subuff.c.o: CMakeFiles/anpnetstack.dir/flags.make
CMakeFiles/anpnetstack.dir/src/subuff.c.o: src/subuff.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/b/Downloads/anp-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building C object CMakeFiles/anpnetstack.dir/src/subuff.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/anpnetstack.dir/src/subuff.c.o   -c /home/b/Downloads/anp-main/src/subuff.c

CMakeFiles/anpnetstack.dir/src/subuff.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/anpnetstack.dir/src/subuff.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/b/Downloads/anp-main/src/subuff.c > CMakeFiles/anpnetstack.dir/src/subuff.c.i

CMakeFiles/anpnetstack.dir/src/subuff.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/anpnetstack.dir/src/subuff.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/b/Downloads/anp-main/src/subuff.c -o CMakeFiles/anpnetstack.dir/src/subuff.c.s

CMakeFiles/anpnetstack.dir/src/subuff.c.o.requires:

.PHONY : CMakeFiles/anpnetstack.dir/src/subuff.c.o.requires

CMakeFiles/anpnetstack.dir/src/subuff.c.o.provides: CMakeFiles/anpnetstack.dir/src/subuff.c.o.requires
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/subuff.c.o.provides.build
.PHONY : CMakeFiles/anpnetstack.dir/src/subuff.c.o.provides

CMakeFiles/anpnetstack.dir/src/subuff.c.o.provides.build: CMakeFiles/anpnetstack.dir/src/subuff.c.o


CMakeFiles/anpnetstack.dir/src/route.c.o: CMakeFiles/anpnetstack.dir/flags.make
CMakeFiles/anpnetstack.dir/src/route.c.o: src/route.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/b/Downloads/anp-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building C object CMakeFiles/anpnetstack.dir/src/route.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/anpnetstack.dir/src/route.c.o   -c /home/b/Downloads/anp-main/src/route.c

CMakeFiles/anpnetstack.dir/src/route.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/anpnetstack.dir/src/route.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/b/Downloads/anp-main/src/route.c > CMakeFiles/anpnetstack.dir/src/route.c.i

CMakeFiles/anpnetstack.dir/src/route.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/anpnetstack.dir/src/route.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/b/Downloads/anp-main/src/route.c -o CMakeFiles/anpnetstack.dir/src/route.c.s

CMakeFiles/anpnetstack.dir/src/route.c.o.requires:

.PHONY : CMakeFiles/anpnetstack.dir/src/route.c.o.requires

CMakeFiles/anpnetstack.dir/src/route.c.o.provides: CMakeFiles/anpnetstack.dir/src/route.c.o.requires
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/route.c.o.provides.build
.PHONY : CMakeFiles/anpnetstack.dir/src/route.c.o.provides

CMakeFiles/anpnetstack.dir/src/route.c.o.provides.build: CMakeFiles/anpnetstack.dir/src/route.c.o


CMakeFiles/anpnetstack.dir/src/timer.c.o: CMakeFiles/anpnetstack.dir/flags.make
CMakeFiles/anpnetstack.dir/src/timer.c.o: src/timer.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/b/Downloads/anp-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Building C object CMakeFiles/anpnetstack.dir/src/timer.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/anpnetstack.dir/src/timer.c.o   -c /home/b/Downloads/anp-main/src/timer.c

CMakeFiles/anpnetstack.dir/src/timer.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/anpnetstack.dir/src/timer.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/b/Downloads/anp-main/src/timer.c > CMakeFiles/anpnetstack.dir/src/timer.c.i

CMakeFiles/anpnetstack.dir/src/timer.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/anpnetstack.dir/src/timer.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/b/Downloads/anp-main/src/timer.c -o CMakeFiles/anpnetstack.dir/src/timer.c.s

CMakeFiles/anpnetstack.dir/src/timer.c.o.requires:

.PHONY : CMakeFiles/anpnetstack.dir/src/timer.c.o.requires

CMakeFiles/anpnetstack.dir/src/timer.c.o.provides: CMakeFiles/anpnetstack.dir/src/timer.c.o.requires
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/timer.c.o.provides.build
.PHONY : CMakeFiles/anpnetstack.dir/src/timer.c.o.provides

CMakeFiles/anpnetstack.dir/src/timer.c.o.provides.build: CMakeFiles/anpnetstack.dir/src/timer.c.o


CMakeFiles/anpnetstack.dir/src/ip_rx.c.o: CMakeFiles/anpnetstack.dir/flags.make
CMakeFiles/anpnetstack.dir/src/ip_rx.c.o: src/ip_rx.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/b/Downloads/anp-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_10) "Building C object CMakeFiles/anpnetstack.dir/src/ip_rx.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/anpnetstack.dir/src/ip_rx.c.o   -c /home/b/Downloads/anp-main/src/ip_rx.c

CMakeFiles/anpnetstack.dir/src/ip_rx.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/anpnetstack.dir/src/ip_rx.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/b/Downloads/anp-main/src/ip_rx.c > CMakeFiles/anpnetstack.dir/src/ip_rx.c.i

CMakeFiles/anpnetstack.dir/src/ip_rx.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/anpnetstack.dir/src/ip_rx.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/b/Downloads/anp-main/src/ip_rx.c -o CMakeFiles/anpnetstack.dir/src/ip_rx.c.s

CMakeFiles/anpnetstack.dir/src/ip_rx.c.o.requires:

.PHONY : CMakeFiles/anpnetstack.dir/src/ip_rx.c.o.requires

CMakeFiles/anpnetstack.dir/src/ip_rx.c.o.provides: CMakeFiles/anpnetstack.dir/src/ip_rx.c.o.requires
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/ip_rx.c.o.provides.build
.PHONY : CMakeFiles/anpnetstack.dir/src/ip_rx.c.o.provides

CMakeFiles/anpnetstack.dir/src/ip_rx.c.o.provides.build: CMakeFiles/anpnetstack.dir/src/ip_rx.c.o


CMakeFiles/anpnetstack.dir/src/ip_tx.c.o: CMakeFiles/anpnetstack.dir/flags.make
CMakeFiles/anpnetstack.dir/src/ip_tx.c.o: src/ip_tx.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/b/Downloads/anp-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_11) "Building C object CMakeFiles/anpnetstack.dir/src/ip_tx.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/anpnetstack.dir/src/ip_tx.c.o   -c /home/b/Downloads/anp-main/src/ip_tx.c

CMakeFiles/anpnetstack.dir/src/ip_tx.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/anpnetstack.dir/src/ip_tx.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/b/Downloads/anp-main/src/ip_tx.c > CMakeFiles/anpnetstack.dir/src/ip_tx.c.i

CMakeFiles/anpnetstack.dir/src/ip_tx.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/anpnetstack.dir/src/ip_tx.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/b/Downloads/anp-main/src/ip_tx.c -o CMakeFiles/anpnetstack.dir/src/ip_tx.c.s

CMakeFiles/anpnetstack.dir/src/ip_tx.c.o.requires:

.PHONY : CMakeFiles/anpnetstack.dir/src/ip_tx.c.o.requires

CMakeFiles/anpnetstack.dir/src/ip_tx.c.o.provides: CMakeFiles/anpnetstack.dir/src/ip_tx.c.o.requires
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/ip_tx.c.o.provides.build
.PHONY : CMakeFiles/anpnetstack.dir/src/ip_tx.c.o.provides

CMakeFiles/anpnetstack.dir/src/ip_tx.c.o.provides.build: CMakeFiles/anpnetstack.dir/src/ip_tx.c.o


CMakeFiles/anpnetstack.dir/src/icmp.c.o: CMakeFiles/anpnetstack.dir/flags.make
CMakeFiles/anpnetstack.dir/src/icmp.c.o: src/icmp.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/b/Downloads/anp-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_12) "Building C object CMakeFiles/anpnetstack.dir/src/icmp.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/anpnetstack.dir/src/icmp.c.o   -c /home/b/Downloads/anp-main/src/icmp.c

CMakeFiles/anpnetstack.dir/src/icmp.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/anpnetstack.dir/src/icmp.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/b/Downloads/anp-main/src/icmp.c > CMakeFiles/anpnetstack.dir/src/icmp.c.i

CMakeFiles/anpnetstack.dir/src/icmp.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/anpnetstack.dir/src/icmp.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/b/Downloads/anp-main/src/icmp.c -o CMakeFiles/anpnetstack.dir/src/icmp.c.s

CMakeFiles/anpnetstack.dir/src/icmp.c.o.requires:

.PHONY : CMakeFiles/anpnetstack.dir/src/icmp.c.o.requires

CMakeFiles/anpnetstack.dir/src/icmp.c.o.provides: CMakeFiles/anpnetstack.dir/src/icmp.c.o.requires
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/icmp.c.o.provides.build
.PHONY : CMakeFiles/anpnetstack.dir/src/icmp.c.o.provides

CMakeFiles/anpnetstack.dir/src/icmp.c.o.provides.build: CMakeFiles/anpnetstack.dir/src/icmp.c.o


CMakeFiles/anpnetstack.dir/src/tcp.c.o: CMakeFiles/anpnetstack.dir/flags.make
CMakeFiles/anpnetstack.dir/src/tcp.c.o: src/tcp.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/b/Downloads/anp-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_13) "Building C object CMakeFiles/anpnetstack.dir/src/tcp.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/anpnetstack.dir/src/tcp.c.o   -c /home/b/Downloads/anp-main/src/tcp.c

CMakeFiles/anpnetstack.dir/src/tcp.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/anpnetstack.dir/src/tcp.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/b/Downloads/anp-main/src/tcp.c > CMakeFiles/anpnetstack.dir/src/tcp.c.i

CMakeFiles/anpnetstack.dir/src/tcp.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/anpnetstack.dir/src/tcp.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/b/Downloads/anp-main/src/tcp.c -o CMakeFiles/anpnetstack.dir/src/tcp.c.s

CMakeFiles/anpnetstack.dir/src/tcp.c.o.requires:

.PHONY : CMakeFiles/anpnetstack.dir/src/tcp.c.o.requires

CMakeFiles/anpnetstack.dir/src/tcp.c.o.provides: CMakeFiles/anpnetstack.dir/src/tcp.c.o.requires
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/tcp.c.o.provides.build
.PHONY : CMakeFiles/anpnetstack.dir/src/tcp.c.o.provides

CMakeFiles/anpnetstack.dir/src/tcp.c.o.provides.build: CMakeFiles/anpnetstack.dir/src/tcp.c.o


CMakeFiles/anpnetstack.dir/src/sock.c.o: CMakeFiles/anpnetstack.dir/flags.make
CMakeFiles/anpnetstack.dir/src/sock.c.o: src/sock.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/b/Downloads/anp-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_14) "Building C object CMakeFiles/anpnetstack.dir/src/sock.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/anpnetstack.dir/src/sock.c.o   -c /home/b/Downloads/anp-main/src/sock.c

CMakeFiles/anpnetstack.dir/src/sock.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/anpnetstack.dir/src/sock.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/b/Downloads/anp-main/src/sock.c > CMakeFiles/anpnetstack.dir/src/sock.c.i

CMakeFiles/anpnetstack.dir/src/sock.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/anpnetstack.dir/src/sock.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/b/Downloads/anp-main/src/sock.c -o CMakeFiles/anpnetstack.dir/src/sock.c.s

CMakeFiles/anpnetstack.dir/src/sock.c.o.requires:

.PHONY : CMakeFiles/anpnetstack.dir/src/sock.c.o.requires

CMakeFiles/anpnetstack.dir/src/sock.c.o.provides: CMakeFiles/anpnetstack.dir/src/sock.c.o.requires
	$(MAKE) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/sock.c.o.provides.build
.PHONY : CMakeFiles/anpnetstack.dir/src/sock.c.o.provides

CMakeFiles/anpnetstack.dir/src/sock.c.o.provides.build: CMakeFiles/anpnetstack.dir/src/sock.c.o


# Object files for target anpnetstack
anpnetstack_OBJECTS = \
"CMakeFiles/anpnetstack.dir/src/init.c.o" \
"CMakeFiles/anpnetstack.dir/src/tap_netdev.c.o" \
"CMakeFiles/anpnetstack.dir/src/utilities.c.o" \
"CMakeFiles/anpnetstack.dir/src/anp_netdev.c.o" \
"CMakeFiles/anpnetstack.dir/src/anpwrapper.c.o" \
"CMakeFiles/anpnetstack.dir/src/arp.c.o" \
"CMakeFiles/anpnetstack.dir/src/subuff.c.o" \
"CMakeFiles/anpnetstack.dir/src/route.c.o" \
"CMakeFiles/anpnetstack.dir/src/timer.c.o" \
"CMakeFiles/anpnetstack.dir/src/ip_rx.c.o" \
"CMakeFiles/anpnetstack.dir/src/ip_tx.c.o" \
"CMakeFiles/anpnetstack.dir/src/icmp.c.o" \
"CMakeFiles/anpnetstack.dir/src/tcp.c.o" \
"CMakeFiles/anpnetstack.dir/src/sock.c.o"

# External object files for target anpnetstack
anpnetstack_EXTERNAL_OBJECTS =

lib/libanpnetstack.so.1.0.1: CMakeFiles/anpnetstack.dir/src/init.c.o
lib/libanpnetstack.so.1.0.1: CMakeFiles/anpnetstack.dir/src/tap_netdev.c.o
lib/libanpnetstack.so.1.0.1: CMakeFiles/anpnetstack.dir/src/utilities.c.o
lib/libanpnetstack.so.1.0.1: CMakeFiles/anpnetstack.dir/src/anp_netdev.c.o
lib/libanpnetstack.so.1.0.1: CMakeFiles/anpnetstack.dir/src/anpwrapper.c.o
lib/libanpnetstack.so.1.0.1: CMakeFiles/anpnetstack.dir/src/arp.c.o
lib/libanpnetstack.so.1.0.1: CMakeFiles/anpnetstack.dir/src/subuff.c.o
lib/libanpnetstack.so.1.0.1: CMakeFiles/anpnetstack.dir/src/route.c.o
lib/libanpnetstack.so.1.0.1: CMakeFiles/anpnetstack.dir/src/timer.c.o
lib/libanpnetstack.so.1.0.1: CMakeFiles/anpnetstack.dir/src/ip_rx.c.o
lib/libanpnetstack.so.1.0.1: CMakeFiles/anpnetstack.dir/src/ip_tx.c.o
lib/libanpnetstack.so.1.0.1: CMakeFiles/anpnetstack.dir/src/icmp.c.o
lib/libanpnetstack.so.1.0.1: CMakeFiles/anpnetstack.dir/src/tcp.c.o
lib/libanpnetstack.so.1.0.1: CMakeFiles/anpnetstack.dir/src/sock.c.o
lib/libanpnetstack.so.1.0.1: CMakeFiles/anpnetstack.dir/build.make
lib/libanpnetstack.so.1.0.1: CMakeFiles/anpnetstack.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/b/Downloads/anp-main/CMakeFiles --progress-num=$(CMAKE_PROGRESS_15) "Linking C shared library lib/libanpnetstack.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/anpnetstack.dir/link.txt --verbose=$(VERBOSE)
	$(CMAKE_COMMAND) -E cmake_symlink_library lib/libanpnetstack.so.1.0.1 lib/libanpnetstack.so.1 lib/libanpnetstack.so

lib/libanpnetstack.so.1: lib/libanpnetstack.so.1.0.1
	@$(CMAKE_COMMAND) -E touch_nocreate lib/libanpnetstack.so.1

lib/libanpnetstack.so: lib/libanpnetstack.so.1.0.1
	@$(CMAKE_COMMAND) -E touch_nocreate lib/libanpnetstack.so

# Rule to build all files generated by this target.
CMakeFiles/anpnetstack.dir/build: lib/libanpnetstack.so

.PHONY : CMakeFiles/anpnetstack.dir/build

CMakeFiles/anpnetstack.dir/requires: CMakeFiles/anpnetstack.dir/src/init.c.o.requires
CMakeFiles/anpnetstack.dir/requires: CMakeFiles/anpnetstack.dir/src/tap_netdev.c.o.requires
CMakeFiles/anpnetstack.dir/requires: CMakeFiles/anpnetstack.dir/src/utilities.c.o.requires
CMakeFiles/anpnetstack.dir/requires: CMakeFiles/anpnetstack.dir/src/anp_netdev.c.o.requires
CMakeFiles/anpnetstack.dir/requires: CMakeFiles/anpnetstack.dir/src/anpwrapper.c.o.requires
CMakeFiles/anpnetstack.dir/requires: CMakeFiles/anpnetstack.dir/src/arp.c.o.requires
CMakeFiles/anpnetstack.dir/requires: CMakeFiles/anpnetstack.dir/src/subuff.c.o.requires
CMakeFiles/anpnetstack.dir/requires: CMakeFiles/anpnetstack.dir/src/route.c.o.requires
CMakeFiles/anpnetstack.dir/requires: CMakeFiles/anpnetstack.dir/src/timer.c.o.requires
CMakeFiles/anpnetstack.dir/requires: CMakeFiles/anpnetstack.dir/src/ip_rx.c.o.requires
CMakeFiles/anpnetstack.dir/requires: CMakeFiles/anpnetstack.dir/src/ip_tx.c.o.requires
CMakeFiles/anpnetstack.dir/requires: CMakeFiles/anpnetstack.dir/src/icmp.c.o.requires
CMakeFiles/anpnetstack.dir/requires: CMakeFiles/anpnetstack.dir/src/tcp.c.o.requires
CMakeFiles/anpnetstack.dir/requires: CMakeFiles/anpnetstack.dir/src/sock.c.o.requires

.PHONY : CMakeFiles/anpnetstack.dir/requires

CMakeFiles/anpnetstack.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/anpnetstack.dir/cmake_clean.cmake
.PHONY : CMakeFiles/anpnetstack.dir/clean

CMakeFiles/anpnetstack.dir/depend:
	cd /home/b/Downloads/anp-main && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/b/Downloads/anp-main /home/b/Downloads/anp-main /home/b/Downloads/anp-main /home/b/Downloads/anp-main /home/b/Downloads/anp-main/CMakeFiles/anpnetstack.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/anpnetstack.dir/depend

