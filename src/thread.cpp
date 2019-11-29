/*

	RandomX Sniffer by tevador <tevador@gmail.com>

	To the extent possible under law, the person who associated CC0 with
	RandomX Sniffer has waived all copyright and related or neighboring rights
	to RandomX Sniffer.

	You should have received a copy of the CC0 legalcode along with this
	work.  If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

*/

#include "thread.h"
#include <winternl.h>

namespace randomx {

	const char* roundNames[] = { "Default", "NegInf", "PosInf", "Zero" };

	std::ostream& operator<<(std::ostream& os, const Round& r) {
		os << roundNames[(unsigned)r];
		return os;
	}

	Thread::Thread(DWORD id) : id_(id), access_(false) {
		if (id) {
			HANDLE handle = OpenThread(THREAD_GET_CONTEXT, false, id);
			if (handle != nullptr) {
				CONTEXT threadContext;
				threadContext.ContextFlags = CONTEXT_FULL;
				if (GetThreadContext(handle, &threadContext)) {
					access_ = true;
					WORD fprc = (threadContext.FltSave.ControlWord & 0xC00) >> 10;
					DWORD mxrc = (threadContext.MxCsr & 0x6000) >> 13;
					if (mxrc != 0) {
						round_ = (Round)mxrc;
					}
					else {
						round_ = (Round)fprc;
					}
				}
				CloseHandle(handle);
			}
		}
	}

}