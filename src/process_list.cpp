/*

	RandomX Sniffer by tevador <tevador@gmail.com>

	To the extent possible under law, the person who associated CC0 with
	RandomX Sniffer has waived all copyright and related or neighboring rights
	to RandomX Sniffer.

	You should have received a copy of the CC0 legalcode along with this
	work.  If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

*/

#include "process_list.h"
#include <winternl.h>
#include <stdexcept>
#include <cassert>

#pragma comment(lib, "ntdll.lib")

namespace randomx {

	ProcessList::ProcessList(SIZE_T allocSize) : bufferSize_(allocSize) {
		buffer_ = VirtualAlloc(nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (buffer_ == nullptr) {
			throw std::bad_alloc();
		}
	}

	ProcessList::~ProcessList() {
		VirtualFree(buffer_, 0, MEM_RELEASE);
	}

	void ProcessList::query() {
		NTSTATUS status;

		if (!NT_SUCCESS(status = NtQuerySystemInformation(SystemProcessInformation, buffer_, bufferSize_, nullptr))) {
			throw std::runtime_error("NtQuerySystemInformation failed");
		}

		data_ = buffer_;
	}

	Process ProcessList::currentProcess() const {
		return Process(data_);
	}

	bool ProcessList::moveNext() {
		auto spi = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(data_);
		auto data = reinterpret_cast<LPBYTE>(data_);
		if (spi->NextEntryOffset) {
			data += spi->NextEntryOffset;
			data_ = data;
			return true;
		}
		return false;
	}
}
