/*

	RandomX Sniffer by tevador <tevador@gmail.com>

	To the extent possible under law, the person who associated CC0 with
	RandomX Sniffer has waived all copyright and related or neighboring rights
	to RandomX Sniffer.

	You should have received a copy of the CC0 legalcode along with this
	work.  If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

*/

#pragma once
#include <Windows.h>
#include "thread.h"

namespace randomx {

	class Process {
	public:
		Process(void* data) : data_(data) {
		}
		DWORD getId() const;
		PWSTR getName() const;
		ULONG getThreadCount() const;
		Thread getThread(ULONG) const;
	private:
		void* data_;
	};

}
