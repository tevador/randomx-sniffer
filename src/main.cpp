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

//command line options:
//-samples N     the number of times processes are sampled (default 5)
//-wait N        time delay between samples (milliseconds, default 50)
//-threshold N   how many different rounding modes are needed for a positive result (default 2)
//-verbose       verbose output
int samples, wait, threshold;
bool verbose;

struct SuspectThread {
	SuspectThread(randomx::Thread t) : id(t.getId()) {
		rounds.push_back(t.getRound());
	}
	DWORD id;
	std::vector<randomx::Round> rounds;
};

struct SuspectProcess {
	SuspectProcess(randomx::Process p) : id(p.getId()), name(p.getName()) {
	}
	void updateThread(randomx::Thread t) {
		auto itt = std::find_if(
			threads.begin(), threads.end(),
			[&t](const SuspectThread& x) { return x.id == t.getId(); });
		if (itt != threads.end()) {
			auto& st = *itt;
			auto ittr = std::find(st.rounds.begin(), st.rounds.end(), t.getRound());
			if (ittr == st.rounds.end()) {
				if (verbose) {
					std::cout << "SuspectProcess " << id << ", old SuspectThread " << t.getId() << ", " << t.getRound() << std::endl;
				}
				st.rounds.push_back(t.getRound());
			}
		}
		else if (t.getRound() != randomx::Round::Default) {
			if (verbose) {
				std::cout << "SuspectProcess " << id << ", new SuspectThread " << t.getId() << ", " << t.getRound() << std::endl;
			}
			threads.push_back(SuspectThread(t));
		}
	}
	std::wstring name;
	DWORD id;
	std::vector<SuspectThread> threads;
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

inline void readOption(const char* option, int argc, char** argv, bool& out) {
	for (int i = 0; i < argc; ++i) {
		if (strcmp(argv[i], option) == 0) {
			out = true;
			return;
		}
	}
	out = false;
}

inline void readIntOption(const char* option, int argc, char** argv, int& out, int defaultValue) {
	for (int i = 0; i < argc - 1; ++i) {
		if (strcmp(argv[i], option) == 0 && (out = atoi(argv[i + 1])) > 0) {
			return;
		}
	}
	out = defaultValue;
}

int main(int argc, char** argv) {

	readIntOption("-samples", argc, argv, samples, 5);
	readIntOption("-wait", argc, argv, wait, 50);
	readIntOption("-threshold", argc, argv, threshold, 2);
	readOption("-verbose", argc, argv, verbose);

	randomx::ProcessList pl;
	std::vector<SuspectProcess> suspectProcesses;
	if (!setPrivilege(SE_DEBUG_NAME, TRUE)) {
		std::cout << "WARNING: Failed to obtain " SE_DEBUG_NAME ". Please run the program as administrator to scan all processes." << std::endl;
	}
	try {
		for (int j = 0; j < samples; ++j) {
			std::this_thread::sleep_for(std::chrono::milliseconds(wait));
			pl.query();
			//All threads with a non-default rounding mode are considered to be suspicious and will be monitored.
			do {
				auto process = pl.currentProcess();
				auto pid = process.getId();
				auto it = std::find_if(
					suspectProcesses.begin(), suspectProcesses.end(),
					[&pid](const SuspectProcess& x) { return x.id == pid; });
				for (unsigned i = 0; i < process.getThreadCount(); ++i) {
					auto thread = process.getThread(i);
					if (thread.canAccess()) {
						auto threadId = thread.getId();
						if (it != suspectProcesses.end()) {
							auto& sp = *it;
							sp.updateThread(thread);
						}
						else if (thread.getRound() != randomx::Round::Default) {
							if (it != suspectProcesses.end()) {
								auto& sp = *it;
								sp.updateThread(thread);
							}
							else {
								SuspectProcess sp(process);
								sp.updateThread(thread);
								suspectProcesses.push_back(sp);
								it = suspectProcesses.end() - 1;
							}
						}
					}
				}
			} while (pl.moveNext());
		}

		bool found = false;
		//The current heuristic only considers that a process is running RandomX
		//if {threshold} different rounding modes were detected.
		//With samples=5 and threshold=2, the false negative chance is about 0.7%.
		//With threshold=1, there may be false positives.
		for (const auto& sp : suspectProcesses) {
			unsigned threads = 0;
			for (const auto& st : sp.threads) {
				if (st.rounds.size() >= threshold) {
					threads++;
				}
			}
			if (threads > 0) {
				found = true;
				std::wcout << "Process " << sp.name;
				std::cout << " (PID " << sp.id << ") may be mining RandomX on ";
				std::cout << threads << " thread(s)";
				std::cout << std::endl;
			}
		}
		if (!found) {
			std::cout << "No suspicious processes were found" << std::endl;
		}
	}
	catch (const std::exception & ex) {
		std::cout << "ERROR: " << ex.what() << std::endl;
		return 1;
	}
	return 0;
}
