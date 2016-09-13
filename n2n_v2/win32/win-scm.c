/*
 * win-scm.c - windows service control manager functions
 *
 * Copyright (c) 2008 Hamish Coleman <hamish@zot.org>
 *               2003 Benjamin Schweizer <gopher at h07 dot org>
 *               1998 Stephen Early <Stephen.Early@cl.cam.ac.uk>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <windows.h>
#include <winsvc.h>
#include <stdio.h>
#include <stdlib.h>

#include "../scm.h"

/* Service status: our current status, and handle on service manager */
SERVICE_STATUS svcStatus;
SERVICE_STATUS_HANDLE svcHandle;

/* global pointer to our service definition */
struct SCM_def *global_sd;

VOID WINAPI ServiceCtrlHandler(DWORD opcode) {
	svcStatus.dwWin32ExitCode = NO_ERROR;
	if (opcode == SERVICE_CONTROL_STOP) {
		svcStatus.dwCurrentState = SERVICE_STOP_PENDING;
		SetServiceStatus( svcHandle, &svcStatus );
		global_sd->stop(NULL);
		return;
	}
	SetServiceStatus( svcHandle, &svcStatus );
}

VOID WINAPI ServiceMain(DWORD argc, LPSTR *argv)
{
	int err;
	/*
	 * TODO
	 * - work out a race-free way to determine the correct sd ptr
	 * - once the correct sd is known, a void* could be passed to all the
	 *   service functions, allowing the service to know
	 */
	struct SCM_def *sd = global_sd;

	/* TODO - use RegisterServiceCtrlHandlerEx and pass the sd to it? */
	svcHandle = RegisterServiceCtrlHandler(sd->name,ServiceCtrlHandler);
	if (!svcHandle) {
		/* FIXME - use SvcReportEvent() */
		printf("RegisterServiceCtrlHandler failed %u\n",
			(unsigned int)GetLastError());
		return;
	}

	svcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	svcStatus.dwCurrentState = 0;
	svcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	svcStatus.dwWin32ExitCode = NO_ERROR;
	svcStatus.dwServiceSpecificExitCode = 0;
	svcStatus.dwCheckPoint = 0;
	svcStatus.dwWaitHint = 5000;

	/* Report initial status to the SCM. */
	svcStatus.dwCurrentState = SERVICE_START_PENDING;
	SetServiceStatus( svcHandle, &svcStatus );

	/*
	 * If there is only one SCM arg, it is just the servicename, so use
	 * the original cmdline instead.
	 * Otherwise, let the SCM args completely override the original ones
	 */
	if (argc==1) {
		argc=sd->argc;
		argv=sd->argv;
	}

	sd->mode=SVC_OK;
	if (sd->init) {
		if ((err=sd->init(argc,argv))!=0) {
			svcStatus.dwCurrentState = SERVICE_STOPPED;
			svcStatus.dwWin32ExitCode = err;
			SetServiceStatus( svcHandle, &svcStatus );
			return;
		}
	}

	svcStatus.dwCurrentState = SERVICE_RUNNING;
	svcStatus.dwWin32ExitCode = NO_ERROR;
	SetServiceStatus( svcHandle, &svcStatus );

	err=sd->main(argc,argv);

	svcStatus.dwCurrentState = SERVICE_STOPPED;
	svcStatus.dwWin32ExitCode = NO_ERROR;
	SetServiceStatus( svcHandle, &svcStatus );
	return;
}

int SCM_Start_Console(struct SCM_def *sd) {

	sd->mode=SVC_CONSOLE;
	int err;
	if (sd->init) {
		err = sd->init(sd->argc,sd->argv);
		if (err!=0) {
			return SVC_FAIL;
		}
	}

	sd->main(sd->argc,sd->argv);
	return SVC_OK;
}

int SCM_Start(struct SCM_def *sd, int argc, char **argv) {
	SERVICE_TABLE_ENTRY ServiceTable[] = {
		{ "", ServiceMain },
		{ NULL, NULL }
	};

	/* save the cmdline for possible use later */
	sd->argc=argc;
	sd->argv=argv;

	global_sd = sd;

	/*
	 * Attempt to detect if we have been run from an interactive session.
	 * checking the environ is still not perfect, since if the
	 * service is set to login as  a user, it gets a USERNAME env
	 * and if that user is currently logged in interactively, it
	 * gets a SESSIONNAME env :-(
	 * So, also check if there is a console window
	 *
	 * Other avenues of investigation:
	 * from http://bytes.com/topic/net/answers/124885-multiple-use-exe-determine-if-running-service
	 * - work out how System.Environment.UserInteractive works
	 * - Check if parent process name is "services.exe"
	 * from http://stackoverflow.com/questions/200163/am-i-running-as-a-service#200183
	 */
        char buf[100];
	if (getenv("USERNAME") && getenv("SESSIONNAME")
	 && GetConsoleTitle((LPTSTR)&buf,sizeof(buf))) {
		return SCM_Start_Console(sd);
	}

	/* try to run as a service */
	/*
	 * Note, this will eventually fail if we are not started as a service
	 * however, it will take an noticably long time to do so, thus we
	 * try to short circuit this delay above.
	 */
	if (StartServiceCtrlDispatcher(ServiceTable)==0) {
		int err = GetLastError();

		if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
			return SCM_Start_Console(sd);
		}

		/* any other error, assume fatal */
		printf("StartServiceCtrlDispatcher failed %d\n", err);
		return SVC_FAIL;
	}
	return SVC_OK;
}

char *SCM_Install(struct SCM_def *sd, char *args) {
	SC_HANDLE schSCManager, schService;

	static char path[MAX_PATH];

	if( !GetModuleFileName( NULL, path, MAX_PATH ) ) {
		printf("GetModuleFileName failed %u\n",
			(unsigned int)GetLastError());
		return NULL;
	}

	/*
	 * Note - the above path calculation does not work for paths containing
	 * spaces.  This is because Windows is stupid, mosttly due to bad
	 * design - see the next below.
	 */

	static char cmdline[MAX_PATH+10];
	if (args) {
		/*
		 * The "BinaryPathName" can also have cmdline params
		 * embedded into it.  Stupid windows
		 */

		snprintf(cmdline,sizeof(cmdline),"\"%s\" %s",path,args);
	} else {
		snprintf(cmdline,sizeof(cmdline),"\"%s\"",path);
	}

	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	schService = CreateService(
		schSCManager,
		sd->name,
		sd->desc,
		SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS,
		SERVICE_AUTO_START,
		SERVICE_ERROR_NORMAL,
		cmdline,
		NULL, NULL, NULL, NULL, NULL);

	if (schService == NULL) {
		printf("CreateService failed\n");
		CloseServiceHandle(schService);
		return NULL;
	}

	CloseServiceHandle(schService);
	return (char *)&path;
}

int SCM_Remove(struct SCM_def *sd) {
	SC_HANDLE schSCManager, schService;

	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCManager == NULL) {
		printf("Couldn't open service manager\n");
		return -1;
	}

	schService = OpenService(schSCManager, sd->name, DELETE);
	if (schService == NULL) {
		printf("Couldn't open %s service\n",sd->name);
		return -1;
	}

	if (!DeleteService(schService)) {
		printf("Couldn't delete %s service\n",sd->name);
		return -1;
	}

	CloseServiceHandle(schService);
	return 0;
}

