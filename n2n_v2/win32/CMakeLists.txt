add_library(n2n_win32
            getopt1.c
            getopt.c
            wintap.c
            win-scm.c
	    n2n_win32.c)
target_link_libraries(n2n_win32 ws2_32)
