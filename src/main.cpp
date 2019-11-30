/*

	RandomX Sniffer by tevador <tevador@gmail.com>

	To the extent possible under law, the person who associated CC0 with
	RandomX Sniffer has waived all copyright and related or neighboring rights
	to RandomX Sniffer.

	You should have received a copy of the CC0 legalcode along with this
	work.  If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

*/

#include <iostream>
#include <chrono>
#include <thread>
#include <string>
#include <vector>
#include <algorithm>
#include "process_list.h"

struct SuspectProcess {
	SuspectProcess(randomx::Process p) : id(p.getId()), name(p.getName()) {
	}
	std::wstring name;
	DWORD id;
	std::vector<DWORD> threads;
};

BOOL setPrivilege(const char* pszPrivilege, BOOL bEnable) {
	HANDLE           hToken = NULL;
	TOKEN_PRIVILEGES tp;
	BOOL             status = FALSE;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		goto cleanup;

	if (!LookupPrivilegeValue(NULL, pszPrivilege, &tp.Privileges[0].Luid))
		goto cleanup;

	tp.PrivilegeCount = 1;

	if (bEnable)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	status =
		AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, 0)
		&&
		GetLastError() == ERROR_SUCCESS;

cleanup:
	if (hToken != NULL)
		CloseHandle(hToken);
	return status;
}

using namespace std::chrono_literals;

int main() {
	randomx::ProcessList pl;
	std::vector<SuspectProcess> suspectProcesses;
	if (!setPrivilege(SE_DEBUG_NAME, TRUE)) {
		std::cout << "WARNING: Failed to obtain " SE_DEBUG_NAME ". Please run the program as administrator to scan all processes." << std::endl;
	}
	try {
		for (int j = 0; j < 5; ++j) {
			std::this_thread::sleep_for(50ms);
			pl.query();
			do {
				auto process = pl.currentProcess();
				for (unsigned i = 0; i < process.getThreadCount(); ++i) {
					auto thread = process.getThread(i);
					if (thread.canAccess()) {
						//consider all threads with non-default rounding mode as suspicious
						//there may be better heuristics
						if (thread.getRound() != randomx::Round::Default) {
							auto threadId = thread.getId();
							auto pid = process.getId();
							auto it = std::find_if(
								suspectProcesses.begin(), suspectProcesses.end(),
								[&pid](const SuspectProcess& x) { return x.id == pid; });
							if (it != suspectProcesses.end()) {
								auto& sp = *it;
								auto itt = std::find(sp.threads.begin(), sp.threads.end(), threadId);
								if (itt == sp.threads.end()) {
									sp.threads.push_back(threadId);
								}
							}
							else {
								SuspectProcess sp(process);
								sp.threads.push_back(threadId);
								suspectProcesses.push_back(sp);
							}
						}
					}
				}
			} while (pl.moveNext());
		}

		if (suspectProcesses.empty()) {
			std::cout << "No suspicious processes were found" << std::endl;
		}
		else {
			for (const auto& sp : suspectProcesses) {
				std::wcout << "Process " << sp.name;
				std::cout << " (PID " << sp.id << ") may be mining RandomX on ";
				std::cout << sp.threads.size() << " thread(s)";
				std::cout << std::endl;
			}
		}
	}
	catch (const std::exception & ex) {
		std::cout << "ERROR: " << ex.what() << std::endl;
		return 1;
	}
	return 0;
}
