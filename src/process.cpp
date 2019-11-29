/*

	RandomX Sniffer by tevador <tevador@gmail.com>

	To the extent possible under law, the person who associated CC0 with
	RandomX Sniffer has waived all copyright and related or neighboring rights
	to RandomX Sniffer.

	You should have received a copy of the CC0 legalcode along with this
	work.  If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

*/

#include "process.h"
#include <winternl.h>

namespace randomx {

	DWORD Process::getId() const {
		auto spi = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(data_);
		return (DWORD)spi->UniqueProcessId;
	}

	PWSTR Process::getName() const {
		auto spi = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(data_);
		if (spi->ImageName.Length > 0) {
			return spi->ImageName.Buffer;
		}
		return nullptr;
	}

	ULONG Process::getThreadCount() const {
		auto spi = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(data_);
		return spi->NumberOfThreads;
	}

	Thread Process::getThread(ULONG index) const {
		auto data = reinterpret_cast<LPBYTE>(data_);
		auto threads = reinterpret_cast<PSYSTEM_THREAD_INFORMATION>(data + sizeof(SYSTEM_PROCESS_INFORMATION));
		return Thread((DWORD)threads[index].ClientId.UniqueThread);
	}
}
